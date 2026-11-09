/*
 * Copyright (C) 2025 Oliver R. Calazans Jeronimo
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org>.
 */

use rustix::event::epoll::{self, CreateFlags, EventData, EventFlags};
use rustix::event::{eventfd, EventfdFlags};
use rustix::fd::OwnedFd;
use rustix::net::{
    bind, recv, socket_with_flags, sockopt, AddressFamily, PacketMembership, Protocol, RecvFlags,
    SockFilter, SocketAddrLinkLayer, SocketFlags, SocketType,
};
use std::fs;
use std::io;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};


const ETH_P_ALL: u16 = 0x0003;


pub struct Sniffer<F>
where
    F: Fn(&[u8]) + Send + Sync + 'static,
{
    iface_name: String,
    ifindex: u32,
    filter: Vec<SockFilter>,
    promisc: bool,
    handler: F,
    state: Mutex<Option<SnifferRuntime>>,
}


struct SnifferRuntime {
    fd: OwnedFd,
    stop_event_fd: OwnedFd,
    epoll_fd: OwnedFd,
    worker_handle: Option<JoinHandle<()>>,
}


impl<F> Sniffer<F>
where
    F: Fn(&[u8]) + Send + Sync + 'static,
{
    pub fn new(
        iface_name : String,
        ifindex    : u32,
        filter     : Vec<SockFilter>,
        promisc    : bool,
        handler    : F,
    ) 
      -> Self
    {
        Self {
            iface_name,
            ifindex,
            filter,
            promisc,
            handler,
            state: Mutex::new(None),
        }
    }


    pub fn start(&self) -> Result<(), io::Error> {
        let mut state_guard = self.state.lock().unwrap();
        if state_guard.is_some() {
            return Ok(());
        }

        let raw_fd = self.create_raw_socket()?;
        self.configure_socket(&raw_fd)?;

        let (stop_event_fd, epoll_fd) = self.setup_epoll(&raw_fd)?;

        let thread_raw_fd   = raw_fd.try_clone()?;
        let thread_stop_fd  = stop_event_fd.try_clone()?;
        let thread_epoll_fd = epoll_fd.try_clone()?;

        let handler_arc   = Arc::new(&self.handler);
        let handler_clone = Arc::clone(&handler_arc);

        let worker_handle = thread::spawn(move || {
            Self::capture_loop(thread_raw_fd, thread_stop_fd, thread_epoll_fd, handler_clone);
        });

        *state_guard = Some(SnifferRuntime {
            fd: raw_fd,
            stop_event_fd,
            epoll_fd,
            worker_handle: Some(worker_handle),
        });

        println!("[+] Sniffer started");
        Ok(())
    }

    
    pub fn stop(&self) {
        let mut state_guard = self.state.lock().unwrap();

        if let Some(mut runtime) = state_guard.take() {
            Self::unblock_epoll_wait(&runtime.stop_event_fd);

            if let Some(handle) = runtime.worker_handle.take() {
                let _ = handle.join();
            }

            self.disable_promiscuous(&runtime.fd);
            println!("[-] Sniffer stopped");
        }
    }


    fn create_raw_socket(&self) -> Result<OwnedFd, io::Error> {
        let protocol = Protocol::from_raw(ETH_P_ALL.to_be() as u32);
        socket_with_flags(
            AddressFamily::PACKET,
            SocketType::RAW,
            SocketFlags::NONBLOCK,
            Some(protocol),
        )
    }


    fn configure_socket(&self, fd: &OwnedFd) -> Result<(), io::Error> {
        self.bind_to_interface(fd)?;
        self.enable_promiscuous(fd)?;
        self.attach_filter(fd)?;
        Ok(())
    }


    fn bind_to_interface(&self, fd: &OwnedFd) -> Result<(), io::Error> {
        let protocol = Protocol::from_raw(ETH_P_ALL.to_be() as u32);
        let addr     = SocketAddrLinkLayer::new(protocol, self.ifindex);
        bind(fd, &addr)?;
        Ok(())
    }


    fn enable_promiscuous(&self, fd: &OwnedFd) -> Result<(), io::Error> {
        if !self.promisc {
            return Ok(());
        }
        sockopt::attach_packet_membership(fd, self.ifindex, PacketMembership::Promiscuous)?;
        Ok(())
    }

    
    fn disable_promiscuous(&self, fd: &OwnedFd) {
        if !self.promisc {
            return;
        }
        if let Err(err) = sockopt::detach_packet_membership(fd, self.ifindex, PacketMembership::Promiscuous) {
            eprintln!("[!] Unable to disable promisc: {}", err);
        }
    }

    
    fn attach_filter(&self, fd: &OwnedFd) -> Result<(), io::Error> {
        if self.filter.is_empty() {
            return Ok(());
        }
        sockopt::attach_filter(fd, &self.filter)?;
        Ok(())
    }


    fn setup_epoll(&self, raw_fd: &OwnedFd) -> Result<(OwnedFd, OwnedFd), io::Error> {
        let stop_event_fd = eventfd(0, EventfdFlags::NONBLOCK | EventfdFlags::CLOEXEC)?;
        let epoll_fd      = epoll::create(CreateFlags::CLOEXEC)?;

        // ID 0 = Raw Socket | ID 1 = Stop Eventfd
        epoll::add(&epoll_fd, raw_fd, EventData::new_u64(0), EventFlags::IN)?;
        epoll::add(&epoll_fd, &stop_event_fd, EventData::new_u64(1), EventFlags::IN)?;

        Ok((stop_event_fd, epoll_fd))
    }


    fn unblock_epoll_wait(stop_event_fd: &OwnedFd) {
        let val = 1u64.to_ne_bytes();
        let _   = rustix::io::write(stop_event_fd, &val);
    }


    fn capture_loop(
        raw_fd        : OwnedFd,
        stop_event_fd : OwnedFd,
        epoll_fd      : OwnedFd,
        handler       : Arc<&F>,
    ) {
        let mut event_list = epoll::EventVec::with_capacity(10);
        let mut buf        = vec![0u8; 65536];

        loop {
            event_list.clear();
            if epoll::wait(&epoll_fd, &mut event_list, -1).is_err() {
                continue;
            }

            for event in &event_list {
                match event.data.u64() {
                    1 => {
                        let mut val = [0u8; 8];
                        let _ = rustix::io::read(&stop_event_fd, &mut val);
                        Self::collect_stats(&raw_fd);
                        return;
                    }
                    0 => {
                        Self::read_available_packets(&raw_fd, &handler, &mut buf);
                    }
                    _ => {}
                }
            }
        }
    }


    fn read_available_packets(raw_fd: &OwnedFd, handler: &F, buf: &mut [u8]) {
        loop {
            match recv(raw_fd, buf, RecvFlags::empty()) {
                Ok(n) => (handler)(&buf[..n]),
                Err(rustix::io::Errno::AGAIN) => break,
                Err(_) => break,
            }
        }
    }

    
    fn collect_stats(fd: &OwnedFd) {
        if let Ok(stats) = sockopt::socket_tpacket_stats(fd) {
            println!("[$] Packets received = {}", stats.tp_packets);
    
            if stats.tp_drops > 0 {
                println!("[!] Packets dropped = {}", stats.tp_drops);
            }
        }
    }
}



fn linktype_of(iface_name: &str) -> Result<i32, io::Error> {
    let path = format!("/sys/class/net/{}/type", iface_name);
    let content = fs::read_to_string(path)?;

    content
        .trim()
        .parse::<i32>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}