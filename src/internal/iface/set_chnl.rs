use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;

// Constante do Wireless Extension para definir frequência/canal
const SIOCSIWFREQ: libc::c_ulong = 0x8B04;

#[repr(C)]
#[derive(Clone, Copy)]
struct IwFreq {
    m: i32,
    e: i16,
    i: u8,
    flags: u8,
}

#[repr(C)]
struct IwReq {
    ifr_name: [u8; 16],
    ifr_data: [u8; 16],
}

// Estrutura auxiliar para garantir o fechamento do socket (equivalente ao defer do Go)
struct SocketGuard {
    fd: RawFd,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Tenta definir o canal da interface sem fio
pub fn try_set_channel(iface_name: &str, channel: i32) -> io::Result<()> {
    // Validação básica do canal (opcional, equivalente ao seu ValidateChannel)
    if channel <= 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Canal inválido"));
    }

    // Cria o socket IPv4 DGRAM
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Garante que o socket será fechado ao sair do escopo (RAII / equivalente ao defer)
    let _guard = SocketGuard { fd };

    let mut wrq = IwReq {
        ifr_name: [0; 16],
        ifr_data: [0; 16],
    };

    // Copia o nome da interface para o buffer ifr_name (garantindo limite de 16 bytes)
    let name_bytes = iface_name.as_bytes();
    if name_bytes.len() >= 16 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Nome da interface muito longo"));
    }
    wrq.ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);

    // Preenche a estrutura IwFreq
    let freq = IwFreq {
        m: channel,
        e: 0,
        i: 0,
        flags: 0,
    };

    // Copia os dados de IwFreq para os primeiros bytes de ifr_data (equivalente ao unsafe pointer do Go)
    unsafe {
        std::ptr::copy_nonoverlapping(
            &freq as *const IwFreq as *const u8,
            wrq.ifr_data.as_mut_ptr(),
            std::mem::size_of::<IwFreq>(),
        );
    }

    // Executa o ioctl
    let res = unsafe {
        libc::ioctl(fd, SIOCSIWFREQ, &mut wrq as *mut IwReq)
    };

    if res < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Define o canal ou encerra o programa em caso de erro (equivalente ao seu MustSetChannel)
pub fn must_set_channel(iface_name: &str, channel: i32) {
    if let Err(err) = try_set_channel(iface_name, channel) {
        eprintln!("Unable to set channel {} on interface {}: {}", channel, iface_name, err);
        std::process::exit(1);
    }
}

fn main() {
    let interface_name = "wlp2s0"; // Substitua pelo nome da sua interface sem fio (ex: wlan0, wlp3s0)
    let channel = 11;              // Canal Wi-Fi desejado

    println!("Tentando definir o canal {} na interface {}...", channel, interface_name);

    // Exemplo 1: Usando a versão segura que retorna Result
    match try_set_channel(interface_name, channel) {
        Ok(()) => println!("Canal alterado com sucesso!"),
        Err(e) => eprintln!("Erro ao alterar o canal: {}. (Lembre-se de rodar com sudo)", e),
    }

    // Exemplo 2: Usando a versão "Must" (encerra o programa automaticamente se falhar)
    // sysconf::must_set_channel(interface_name, channel);
}