use std::io::{self, Write};



pub fn abort(error: impl Into<String>) -> ! {
    eprintln!("[ ERROR ] {}", error.into());
    std::process::exit(1);
}



#[inline]
pub fn inline_display(message: &str) {
    print!("\r{}", message);
    io::stdout().flush().unwrap();
}