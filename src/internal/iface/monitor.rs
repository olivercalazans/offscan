// src/main.rs
//
// Equivalente Rust do pacote ifmode — sem libc (rustix + linux_raw).
// Linux-only. Rode como root: sudo ./ifmode --mon  (ou --man)
//
// CORREÇÕES IMPORTANTES vs. versão anterior:
//   - IFACE_INDEX removido: resolvido em runtime pelo nome em /sys.
//   - Sanity check antes de derrubar/deletar: confirma que a interface é Wi-Fi.
//   - SO_RCVTIMEO de 5s no socket netlink: evita recv bloqueante infinito.
//   - Imports corrigidos: SocketType, netlink::SocketAddrNetlink.
//   - Protocol::from_raw agora usa NonZeroU32 (exigência do rustix 1.1).
//   - fs::read_to_string usa std::io::Result (não rustix::io::Errno).

use rustix::fd::OwnedFd;
use rustix::io;
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{self, AddressFamily, Protocol, RecvFlags, SendFlags, SocketType};
use rustix::net::sockopt::{set_socket_timeout, Timeout};
use std::collections::HashMap;
use std::fs;
use std::num::NonZeroU32;
use std::process;
use std::time::Duration;

// ============================================================
// Interface alvo (apenas o NOME é hardcoded — o índice é resolvido em runtime)
// ============================================================
const IFACE_NAME: &str = "wlp2s0";

// ============================================================
// Constantes (espelham consts.go)
// ============================================================
const NL80211_FAMILY_NAME: &str = "nl80211";

const NL80211_CMD_NEW_INTERFACE: u8 = 7;
const NL80211_CMD_DEL_INTERFACE: u8 = 8;

const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;
const NL80211_ATTR_IFTYPE: u16 = 5;

const NL80211_IFTYPE_MANAGED: u32 = 2;
const NL80211_IFTYPE_MONITOR: u32 = 6;

const RTM_NEWLINK: u16 = 16;
const IFF_UP: u32 = 0x1;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;

const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const NETLINK_ROUTE: u32 = 0;
const NETLINK_GENERIC: u32 = 16;

const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE: u16 = 0x3;

// ============================================================
// Helpers de atributos
// ============================================================
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn genl_hdr(cmd: u8, version: u8) -> Vec<u8> {
    vec![cmd, version, 0, 0]
}

fn put_attr(mut buf: Vec<u8>, typ: u16, data: &[u8]) -> Vec<u8> {
    let length = 4 + data.len();
    let aligned = align4(length);
    let mut attr = vec![0u8; aligned];
    attr[0..2].copy_from_slice(&(length as u16).to_le_bytes());
    attr[2..4].copy_from_slice(&typ.to_le_bytes());
    attr[4..4 + data.len()].copy_from_slice(data);
    buf.extend_from_slice(&attr);
    buf
}

fn put_u32_attr(buf: Vec<u8>, typ: u16, v: u32) -> Vec<u8> {
    put_attr(buf, typ, &v.to_le_bytes())
}

fn put_string_attr(buf: Vec<u8>, typ: u16, s: &str) -> Vec<u8> {
    let mut data = s.as_bytes().to_vec();
    data.push(0);
    put_attr(buf, typ, &data)
}

fn parse_attrs(buf: &[u8]) -> HashMap<u16, Vec<u8>> {
    let mut out = HashMap::new();
    let mut buf = buf;
    while buf.len() >= 4 {
        let alen = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        let atyp = u16::from_le_bytes([buf[2], buf[3]]);
        if alen < 4 || alen > buf.len() {
            break;
        }
        out.insert(atyp & 0x3fff, buf[4..alen].to_vec());
        let next = align4(alen);
        if next > buf.len() {
            break;
        }
        buf = &buf[next..];
    }
    out
}

// ============================================================
// Conexão netlink — via rustix (sem libc)
// ============================================================
struct NlConn {
    fd: OwnedFd,
    seq: u32,
}

impl NlConn {
    fn new(proto: u32) -> io::Result<Self> {
        // Para NETLINK_ROUTE (0), protocolo é None.
        // Para NETLINK_GENERIC (16), passa o valor bruto em NonZeroU32.
        let protocol = if proto == 0 {
            None
        } else {
            Some(Protocol::from_raw(
                NonZeroU32::new(proto).expect("protocol != 0"),
            ))
        };

        let fd = net::socket(AddressFamily::NETLINK, SocketType::RAW, protocol)?;

        // Timeout de 5s: evita recv bloqueante infinito.
        // Se sua versão do rustix não expuser set_socket_timeout, comente a linha.
let _ = set_socket_timeout(&fd, Timeout::Recv, Some(Duration::from_secs(5)));
        let addr = SocketAddrNetlink::new(0, 0);
        net::bind(&fd, &addr)?;

        Ok(NlConn { fd, seq: 0 })
    }

    fn send(&mut self, msg_type: u16, flags: u16, payload: &[u8]) -> io::Result<u32> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let total_len = 16 + payload.len();
        let mut msg = vec![0u8; total_len];

        msg[0..4].copy_from_slice(&(total_len as u32).to_le_bytes());
        msg[4..6].copy_from_slice(&msg_type.to_le_bytes());
        msg[6..8].copy_from_slice(&flags.to_le_bytes());
        msg[8..12].copy_from_slice(&seq.to_le_bytes());
        // msg[12..16] = pid (0)
        msg[16..].copy_from_slice(payload);

        let dst = SocketAddrNetlink::new(0, 0); // kernel
        net::sendto(&self.fd, &msg, SendFlags::empty(), &dst)?;
        Ok(seq)
    }

    fn recv(&self, seq: u32, skip_genl: bool) -> io::Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; 8192];

        loop {
            let (_, n, _) = net::recvfrom(&self.fd, &mut buf[..], RecvFlags::empty())?;
            if n == 0 {
                continue;
            }

            let mut offset = 0usize;
            while offset + 16 <= n {
                let msg_len =
                    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
                if msg_len < 16 || offset + msg_len > n {
                    break;
                }
                let msg_type =
                    u16::from_le_bytes(buf[offset + 4..offset + 6].try_into().unwrap());
                let msg_seq =
                    u32::from_le_bytes(buf[offset + 8..offset + 12].try_into().unwrap());
                let data = &buf[offset + 16..offset + msg_len];

                let aligned = align4(msg_len);
                if offset + aligned > n {
                    break;
                }
                offset += aligned;

                if msg_seq != seq {
                    continue;
                }

                match msg_type {
                    NLMSG_ERROR => {
                        if data.len() < 4 {
                            return Err(io::Errno::INVAL.into());
                        }
                        let code = i32::from_le_bytes(data[0..4].try_into().unwrap());
                        if code == 0 {
                            return Ok(None); // ACK OK
                        }
                        // code vem negativo (ex.: -95 = EOPNOTSUPP).
                        // from_raw_os_error espera o valor positivo.
                        return Err(io::Errno::from_raw_os_error(-code).into());
                    }
                    NLMSG_DONE => return Ok(None),
                    _ => {
                        if skip_genl {
                            if data.len() < 4 {
                                return Err(io::Errno::INVAL.into());
                            }
                            return Ok(Some(data[4..].to_vec()));
                        }
                        return Ok(Some(data.to_vec()));
                    }
                }
            }
        }
    }
}

// ============================================================
// Resolve família genl
// ============================================================
fn resolve_genl_family(name: &str) -> io::Result<u16> {
    let mut c = NlConn::new(NETLINK_GENERIC)?;

    let payload = genl_hdr(CTRL_CMD_GETFAMILY, 1);
    let payload = put_string_attr(payload, CTRL_ATTR_FAMILY_NAME, name);

    let seq = c.send(GENL_ID_CTRL, NLM_F_REQUEST, &payload)?;
    let data = c.recv(seq, true)?;

    let data = match data {
        Some(d) => d,
        None => return Err(io::Errno::NOENT.into()),
    };

    let attrs = parse_attrs(&data);
    match attrs.get(&CTRL_ATTR_FAMILY_ID) {
        Some(id_buf) if id_buf.len() >= 2 => Ok(u16::from_le_bytes([id_buf[0], id_buf[1]])),
        _ => Err(io::Errno::NOENT.into()),
    }
}

// ============================================================
// nl80211
// ============================================================
struct Nl80211 {
    conn: NlConn,
    fam_id: u16,
    ver: u8,
}

impl Nl80211 {
    fn new() -> io::Result<Self> {
        let fam_id = resolve_genl_family(NL80211_FAMILY_NAME)?;
        let conn = NlConn::new(NETLINK_GENERIC)?;
        Ok(Nl80211 { conn, fam_id, ver: 1 })
    }

    fn exec(&mut self, cmd: u8, attrs: &[u8]) -> io::Result<()> {
        let mut payload = genl_hdr(cmd, self.ver);
        payload.extend_from_slice(attrs);
        let seq = self
            .conn
            .send(self.fam_id, NLM_F_REQUEST | NLM_F_ACK, &payload)?;
        self.conn.recv(seq, true)?;
        Ok(())
    }

    fn delete_interface(&mut self, ifindex: i32) -> io::Result<()> {
        let attrs = put_u32_attr(Vec::new(), NL80211_ATTR_IFINDEX, ifindex as u32);
        self.exec(NL80211_CMD_DEL_INTERFACE, &attrs)
    }

    fn create_interface(&mut self, wiphy: i32, name: &str, iftype: u32) -> io::Result<()> {
        let attrs = Vec::new();
        let attrs = put_u32_attr(attrs, NL80211_ATTR_WIPHY, wiphy as u32);
        let attrs = put_string_attr(attrs, NL80211_ATTR_IFNAME, name);
        let attrs = put_u32_attr(attrs, NL80211_ATTR_IFTYPE, iftype);
        self.exec(NL80211_CMD_NEW_INTERFACE, &attrs)
    }
}

// ============================================================
// rtnetlink: link up/down
// ============================================================
fn set_link_up(ifindex: i32, up: bool) -> io::Result<()> {
    let mut c = NlConn::new(NETLINK_ROUTE)?;

    // struct ifinfomsg: u8 family; u8 pad; u16 type; int index; u32 flags; u32 change;
    let mut ifinfo = vec![0u8; 16];
    ifinfo[0] = 0; // AF_UNSPEC
    ifinfo[4..8].copy_from_slice(&(ifindex as u32).to_le_bytes());

    let flags: u32 = if up { IFF_UP } else { 0 };
    ifinfo[8..12].copy_from_slice(&flags.to_le_bytes());
    ifinfo[12..16].copy_from_slice(&IFF_UP.to_le_bytes());

    let seq = c.send(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, &ifinfo)?;
    c.recv(seq, false)?;
    Ok(())
}

// ============================================================
// sysfs (usa std::io::Result, não rustix::io::Errno)
// ============================================================
fn phy_index(iface: &str) -> std::io::Result<i32> {
    let path = format!("/sys/class/net/{}/phy80211/index", iface);
    let data = fs::read_to_string(&path)?;
    data.trim()
        .parse::<i32>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn ifindex_from_name(iface: &str) -> std::io::Result<i32> {
    let path = format!("/sys/class/net/{}/ifindex", iface);
    let data = fs::read_to_string(&path)?;
    data.trim()
        .parse::<i32>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

// ============================================================
// Sanity check — NUNCA opera em interface errada
// ============================================================
fn sanity_check(iface: &str, expected_index: i32) -> Result<(), String> {
    let actual = ifindex_from_name(iface)
        .map_err(|e| format!("ifindex for {} not found: {}", iface, e))?;
    if actual != expected_index {
        return Err(format!(
            "index mismatch for {}: expected {}, got {}",
            iface, expected_index, actual
        ));
    }
    let phy_path = format!("/sys/class/net/{}/phy80211", iface);
    if !std::path::Path::new(&phy_path).exists() {
        return Err(format!(
            "{} is not a WiFi interface (no {}). Refusing to operate.",
            iface, phy_path
        ));
    }
    Ok(())
}

// ============================================================
// switchMode
// ============================================================
fn switch_mode(iface: &str, iface_index: i32, iftype: u32, label: &str) {
    let wiphy = match phy_index(iface) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Unable to resolve phy for {}: {}", iface, e);
            process::exit(1);
        }
    };

    let mut dev = match Nl80211::new() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Unable to open nl80211 socket: {}", e);
            process::exit(1);
        }
    };

    if let Err(e) = set_link_up(iface_index, false) {
        eprintln!("Unable to set interface {} down: {}", iface, e);
        process::exit(1);
    }

    if let Err(e) = dev.delete_interface(iface_index) {
        eprintln!("Unable to delete interface {}: {}", iface, e);
        process::exit(1);
    }

    if let Err(e) = dev.create_interface(wiphy, iface, iftype) {
        eprintln!(
            "Unable to create interface {} on {} mode: {}",
            iface, label, e
        );
        process::exit(1);
    }

    // Após recriar, o ifindex pode ter mudado — relê do sysfs.
    match ifindex_from_name(iface) {
        Ok(new_idx) => {
            if let Err(e) = set_link_up(new_idx, true) {
                eprintln!("Unable to set interface {} up: {}", iface, e);
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Unable to resolve new ifindex for {}: {}", iface, e);
            process::exit(1);
        }
    }
}

// ============================================================
// CLI + main
// ============================================================
fn display_help() {
    println!("\n### INTERFACE MODE (Rust + rustix, sem libc)\n");
    println!("    Interface alvo: {} (índice resolvido em runtime)", IFACE_NAME);
    println!("    Uso: $ sudo ./ifmode --mon   (ou --man)\n");
    println!("    --mon : Monitor mode");
    println!("    --man : Managed mode\n");
    println!("    IMPORTANTE: isso derruba e recria a interface.");
    println!("    Não rode via SSH pela mesma interface. Use console local");
    println!("    ou uma segunda interface Wi-Fi (dongle USB) como alvo.");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut mon = false;
    let mut man = false;

    for a in &args[1..] {
        match a.as_str() {
            "--mon" => mon = true,
            "--man" => man = true,
            "-h" | "--help" => {
                display_help();
                return;
            }
            _ => {}
        }
    }

    if !mon && !man {
        eprintln!("It's necessary to select a mode: --mon or --man");
        process::exit(1);
    }
    if mon && man {
        eprintln!("Select only one mode: --mon or --man");
        process::exit(1);
    }

    // Resolve o índice real em runtime (o kernel atribui, não é estável).
    let iface_index = ifindex_from_name(IFACE_NAME).unwrap_or_else(|e| {
        eprintln!("Unable to resolve ifindex for {}: {}", IFACE_NAME, e);
        process::exit(1);
    });

    // Sanity check: garante que IFACE_NAME é Wi-Fi e o índice confere.
    if let Err(e) = sanity_check(IFACE_NAME, iface_index) {
        eprintln!("Sanity check failed: {}", e);
        process::exit(1);
    }

    eprintln!(
        "[*] Target: {} (ifindex {}) — switching to {} mode",
        IFACE_NAME,
        iface_index,
        if mon { "monitor" } else { "managed" }
    );

    if mon {
        switch_mode(IFACE_NAME, iface_index, NL80211_IFTYPE_MONITOR, "monitor");
    }
    if man {
        switch_mode(IFACE_NAME, iface_index, NL80211_IFTYPE_MANAGED, "managed");
    }
}