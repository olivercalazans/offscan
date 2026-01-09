use std::{thread, time::Duration};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crate::engines::FakeApsArgs;
use crate::iface::IfaceManager;
use crate::builders::Frames;
use crate::sockets::Layer2Socket;
use crate::generators::RandomValues;
use crate::utils::{ CtrlCHandler, inline_display };


pub struct FakeAps {
    args: FakeApsArgs,
}


impl FakeAps {

    pub fn new(args: FakeApsArgs) -> Self {
        Self { args, }
    }



    pub fn execute(&mut self) {
        self.set_channel();
    }



    fn set_channel(&self) {
        if self.channel.is_none() {
            return;
        }
        
        let done = IfaceManager::set_channel(&self.args.iface, self.args.channel);

        if !done {
            abort(
                format!(
                    "Uneable to set channel {} on interface {}", 
                    self.args.iface, 
                    self.args.channel
                )
            )
        }
    }

}