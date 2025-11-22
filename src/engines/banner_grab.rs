use std::{net::TcpStream, io::{Write, BufRead, BufReader}, time::Duration, collections::BTreeMap};
use std::sync::mpsc;
use std::thread;
use crate::arg_parser::BannerArgs;



pub struct BannerGrabber {
    target_ip: String,
    result:    BTreeMap<u16, String>,
    refused:   u32,
    timeout:   u32,
    errors:    u32,
}



impl BannerGrabber {

    pub fn new(args: BannerArgs) -> Self {
        Self { 
            target_ip: args.target_ip.to_string(),
            result:    BTreeMap::new(),
            refused:   0,
            timeout:   0,
            errors:    0,
        }
    }



    pub fn execute(&mut self) {
        self.ssh(22);
        self.http(80);
        self.http(8080);
        self.ipp(631);
        self.display_errors();
        self.display_result();
    }



    fn display_errors(&self) {
        println!("Connection error.....: {}", self.errors);
        println!("No response (timeout): {}", self.timeout);
        println!("Refused connections..: {}", self.refused);
        println!("");
    }



    fn display_result(&self) {
        println!("PORT   BANNER/SERVICE");
        println!("-----  -----------------");
        
        for (port, response) in &self.result {
            println!("{:<5}  {}", port, response);
        }
    }



    fn connect_with_timeout(&mut self, port: u16) -> Option<TcpStream> {
        let target = format!("{}:{}", self.target_ip, port);
        let (tx, rx) = mpsc::channel();
        
        thread::spawn(move || {
            let result = TcpStream::connect(&target);
            let _ = tx.send(result);
        });

        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(stream)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                return Some(stream);
            }
            Ok(Err(_)) => {
                self.refused += 1;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.timeout += 1;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.errors += 1;
            }
        }

        None
    }



    fn ssh(&mut self, port: u16) {
        let stream = match self.connect_with_timeout(port) {
            Some(stream) => stream,
            None         => return,
        };

        let mut banner_line = String::new();
        let mut reader = BufReader::new(stream);
    
        if reader.read_line(&mut banner_line).is_ok() {
            self.result.insert(port, banner_line.trim().to_string());
        }
    }



    fn http(&mut self, port: u16) {
        let mut stream = match self.connect_with_timeout(port) {
            Some(stream) => stream,
            None => return,
        };

        if stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").is_err() {
            return;
        }

        let reader = BufReader::new(stream);

        for line in reader.lines() {
            let line = match line {
                Ok(line) => line,
                Err(_)   => break,
            };

            if line.trim().is_empty() {
                break;
            }

            if line.to_lowercase().starts_with("server:") {
                self.result.insert(port, line);
                break;
            }
        }
    }
    


    fn ipp(&mut self, port: u16) {
        let mut stream = match self.connect_with_timeout(port) {
            Some(stream) => stream,
            None => return,
        };

        let request = format!(
            "GET /ipp/print HTTP/1.1\r\n\
            Host: localhost:{}\r\n\
            User-Agent: Rust IPP Scanner\r\n\
            Accept: application/ipp\r\n\
            Connection: close\r\n\r\n", 
            port
        );

        if stream.write_all(request.as_bytes()).is_err() {
            return;
        }

        let reader = BufReader::new(stream);
        let mut server_header = None;
        let mut ipp_info = None;

        for line in reader.lines() {
            let line = match line {
                Ok(line) => line,
                Err(_) => break,
            };

            if line.trim().is_empty() {
                break;
            }

            if line.to_lowercase().starts_with("server:") && server_header.is_none() {
                server_header = Some(line.clone());
            }

            if line.to_lowercase().contains("ipp") || line.to_lowercase().contains("cups") {
                ipp_info = Some(line.clone());
            }

            if line.to_lowercase().starts_with("x-") || 
               line.to_lowercase().contains("printer") ||
               line.to_lowercase().contains("print") {
                if ipp_info.is_none() {
                    ipp_info = Some(line.clone());
                }
            }
        }

        if let Some(server) = server_header {
            self.result.insert(port, server);
        } else if let Some(ipp) = ipp_info {
            self.result.insert(port, format!("IPP Service: {}", ipp));
        } else {
            self.result.insert(port, "IPP/Print Service (no banner)".to_string());
        }
    }
}