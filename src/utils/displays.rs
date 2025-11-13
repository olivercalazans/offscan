use std::io::{self, Write};



pub fn abort(error: impl Into<String>) -> ! {
    eprintln!("[ ERROR ] {}", error.into());
    std::process::exit(1);
}


pub fn inline_display(message: &str) {
    print!("\r{}", message);
    io::stdout().flush().unwrap();
}