use std::{net::TcpStream, io::{Write, BufRead, BufReader}, time::Duration, collections::BTreeMap};
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
        self.ipp(631);
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
            Err(_)     => { return; }
        };

        if stream.set_read_timeout(Some(Duration::from_secs(5))).is_err() {
            return;
        }

        let mut banner_line = String::new();
        let mut reader      = BufReader::new(stream);
    
        if reader.read_line(&mut banner_line).is_ok() {
            self.result.insert(port, banner_line.trim().to_string());
        }
    }



    fn http(&mut self, port: u16) {
        let mut stream = match TcpStream::connect(format!("{}:{}", self.target_ip, port)) {
            Ok(stream) => { stream }
            Err(_)     => { return; }
        };

        if stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").is_err() {
            return;
        }

        let reader = BufReader::new(stream);

        for line in reader.lines() {
            let line = match line {
                Ok(line) => line,
                Err(_) => break,
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
        let mut stream = match TcpStream::connect(format!("{}:{}", self.target_ip, port)) {
            Ok(stream) => { stream }
            Err(_)     => { return; }
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
        let mut ipp_info      = None;

        for line in reader.lines() {
            let line = match line {
                Ok(line) => line,
                Err(_)   => break,
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