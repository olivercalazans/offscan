use std::{
    net::TcpStream, io::{Read, Write, BufRead, BufReader}, time::Duration, collections::BTreeMap
};
use crate::arg_parser::BannerArgs;
use crate::utils::abort;



pub struct BannerGrabber {
    target_ip: String,
    result:    BTreeMap<u16, String>,
    error:     BTreeMap<u16, String>,
}



impl BannerGrabber {

    pub fn new(args: BannerArgs) -> Self {
        Self { 
            target_ip: args.target_ip.to_string(),
            result:    BTreeMap::new(),
            error:     BTreeMap::new(),
        }
    }



    pub fn execute(&mut self) {
        self.ssh();
        self.http();
        self.display_result();
    }



    fn connect_to_target(&self, port: u16) -> TcpStream {
        let stream = match TcpStream::connect(format!("{}:{}", self.target_ip, port)) {
            Ok(stream) => { stream }
            Err(e)     => abort(&format!("Failed to connect to {}: {}", self.target_ip, e)),
        };
        
        stream
    }



    fn display_result(&self) {
        for (port, respose) in &self.result {
            println!("{:<5}  {}", port, respose);
        }
    }



    fn ssh(&mut self) {
        let stream = self.connect_to_target(22);

        if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(5))) {
            abort(&format!("Falha ao configurar timeout: {}", e));
        }

        let mut banner_line = String::new();
        let mut reader      = BufReader::new(stream);
    
        match reader.read_line(&mut banner_line) {
            Ok(_)  => { self.result.insert(22, banner_line.trim().to_string()); }
            Err(e) => { self.error.insert(22, e.to_string()); }
        }
    }



    fn http(&mut self) {
        let mut stream = self.connect_to_target(80);

        if let Err(e) = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n") {
            abort(&format!("Failed to send data: {}", e));
        }

        let reader = BufReader::new(stream);
        let mut server_header = None;

        for line in reader.lines() {
            let line = match line {
                Ok(line) => line,
                Err(_) => break,
            };

            if line.trim().is_empty() {
                break;
            }

            if line.to_lowercase().starts_with("server:") {
                server_header = Some(line);
                break;
            }
        }

        let result = server_header.unwrap_or_else(|| "Server: Not found".to_string());
        self.result.insert(80, result);
    }

}