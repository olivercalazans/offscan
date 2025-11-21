use std::{net::TcpStream, io::{Read, Write}};
use crate::arg_parser::BannerArgs;
use crate::utils::abort;



pub struct BannerGrabber {
    target_ip: String,
}


impl BannerGrabber {

    pub fn new(args: BannerArgs) -> Self {
        Self { target_ip: args.target_ip.to_string() }
    }



    pub fn execute(&self) {
        self.http();
    }



    fn http(&self) {
        let mut stream = match TcpStream::connect(format!("{}:80", self.target_ip)) {
            Ok(stream) => stream,
            Err(e) => abort(&format!("Falha ao conectar a {}: {}", self.target_ip, e)),
        };

        if let Err(e) = stream.write_all(b"GET / HTTP/1.0\r\n\r\n") {
            abort(&format!("Failed to send data: {}", e));
        }

        let mut buffer = Vec::new();
        if let Err(e) = stream.read_to_end(&mut buffer) {
            abort(&format!("Failed to read response: {}", e));
        }

        println!("Resposta do servidor:\n{}", String::from_utf8_lossy(&buffer));
    }

}