use std::{
    net::TcpStream, io::{Write, BufRead, BufReader}, time::Duration, collections::BTreeMap
};
use crate::arg_parser::BannerArgs;



pub struct BannerGrabber {
    target_ip: String,
    result:    BTreeMap<u16, String>,
}



impl BannerGrabber {

    pub fn new(args: BannerArgs) -> Self {
        Self { 
            target_ip: args.target_ip.to_string(),
            result:    BTreeMap::new(),
        }
    }



    pub fn execute(&mut self) {
        self.ssh(22);
        self.http(80);
        self.http(8080);
        self.display_result();
    }



    fn display_result(&self) {
        for (port, respose) in &self.result {
            println!("{:<5}  {}", port, respose);
        }
    }



    fn ssh(&mut self, port: u16) {
        let stream = match TcpStream::connect(format!("{}:{}", self.target_ip, port)) {
            Ok(stream) => { stream }
            Err(e)     => {
                self.result.insert(
                    port, format!("Failed to connect to {}:{} {}", self.target_ip, port, e)
                );
                return;
            }
        };

        if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(5))) {
            self.result.insert(port, format!("Failed to set timeout: {}", e));
            return;
        }

        let mut banner_line = String::new();
        let mut reader      = BufReader::new(stream);
    
        match reader.read_line(&mut banner_line) {
            Ok(_)  => { self.result.insert(port, banner_line.trim().to_string()); }
            Err(e) => { self.result.insert(port, e.to_string()); }
        }
    }



    fn http(&mut self, port: u16) {
        let mut stream = match TcpStream::connect(format!("{}:{}", self.target_ip, port)) {
            Ok(stream) => { stream }
            Err(e)     => {
                self.result.insert(port, format!("Failed to connect to {}:{} {}", self.target_ip, port, e));
                return;
            }
        };

        if let Err(e) = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n") {
            self.result.insert(port, format!("Failed to send data: {}", e));
            return;
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
        self.result.insert(port, result);
    }

}