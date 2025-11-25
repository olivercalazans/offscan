pub mod displays;
pub use displays::*;

pub mod dns;
pub use dns::get_host_name;

pub mod first_and_last_ips;
pub use first_and_last_ips::get_first_and_last_ips;