use clap::Parser;


#[derive(Parser)]
#[command(
    name = "info",
    about = 
"This command display some information of all network interfaces.
These information are:
\t- Name
\t- State
\t- Type
\t- MAC
\t- IP
\t- Network Address and Mask (CIDR)
\t- Number of valid hosts
\t- MTU
\t- Gateway MAC
\t- Gateway IP"
)]
pub struct NetInfoArgs;