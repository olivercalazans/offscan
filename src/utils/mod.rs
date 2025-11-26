pub mod ctrl_c_handler;
pub use ctrl_c_handler::CtrlCHandler;

pub mod displays;
pub use displays::*;

pub mod dns;
pub use dns::get_host_name;

pub mod first_and_last_ip;
pub use first_and_last_ip::get_first_and_last_ip;