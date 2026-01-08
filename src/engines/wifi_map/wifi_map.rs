use std::{collections::BTreeMap, mem};
use crate::engines::wifi_map::{WmapArgs, SysSniff, MonitorSniff, WifiData};



pub struct WifiMapper {
    args  : WmapArgs,
    wifis : BTreeMap<String, WifiData>,
}


impl WifiMapper {
    
    pub fn new(args: WmapArgs) -> Self {
        Self { args, wifis : BTreeMap::new(), }
    }



    pub fn execute(&mut self) {
        match self.args.monitor {
            true  => self.monitor_sniff(),
            false => self.sys_sniff(),
        }

        self.display_results();
    }



    fn monitor_sniff(&mut self) {
        let mut mon_sniff = MonitorSniff::new(self.args.iface.clone(), &mut self.wifis);
        mon_sniff.execute_monitor_sniff();
    }



    fn sys_sniff(&mut self) {
        let mut sys_sniff = SysSniff::new(self.args.iface.clone(), &mut self.wifis);
        sys_sniff.execute_sys_sniff();
    }



     fn display_results(&mut self) {
        let max_len = self.wifis.keys().map(String::len).max().unwrap_or(4);
        let wifis   = mem::take(&mut self.wifis);

        Self::display_header(max_len);
        
        for (name, info) in wifis.into_iter() {
            Self::display_wifi_info(&name, &info, max_len);
        }
    }



    fn display_header(max_len: usize) {
        println!(
            "\n{:<width$}  {:<17}  {}  {}", 
            "SSID", "MAC", "Channel", "Frequency", width = max_len
        );
        println!("{}  {}  {}  {}", "-".repeat(max_len), "-".repeat(17), "-".repeat(7), "-".repeat(9));
    }



    fn display_wifi_info(name: &str, info: &WifiData, max_len: usize) {
        let macs: Vec<&String> = info.bssids.iter().collect();
        
        println!(
            "{:<width$}  {}  {:<7}  {}G",
            name, 
            macs.first().unwrap_or(&&"N/A".to_string()), 
            info.channel,
            info.frequency,
            width = max_len
        );
        
        for mac in macs.iter().skip(1) {
            println!("{:<width$}  {}", "", mac, width = max_len);
        }
    }

}



impl crate::EngineTrait for WifiMapper {
    type Args = WmapArgs;
    
    fn new(args: Self::Args) -> Self {
        WifiMapper::new(args)
    }
    
    fn execute(&mut self) {
        self.execute();
    }
}