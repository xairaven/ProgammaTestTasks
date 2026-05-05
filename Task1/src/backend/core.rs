use crate::commands::{EngineEvent, UiCommand};
use crate::errors::ProjectError;
use crossbeam::channel::{Receiver, Sender, TryRecvError};

#[derive(Debug)]
pub struct Engine {
    // Channels
    pub ui_command_rx: Receiver<UiCommand>,
    pub engine_event_tx: Sender<EngineEvent>,
    pub errors_tx: Sender<ProjectError>,
}

impl Engine {
    pub fn run(&mut self) {
        loop {
            let command = match self.ui_command_rx.try_recv() {
                Ok(value) => value,
                Err(TryRecvError::Disconnected) => return,
                Err(TryRecvError::Empty) => continue,
            };

            match command {
                UiCommand::Start(info) => {
                    todo!()
                },
                UiCommand::Exit => return,
            }
        }
    }
}
