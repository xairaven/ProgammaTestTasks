use crate::config::Config;
use crate::errors::ProjectError;
use crossbeam::channel::{Receiver, Sender};

#[derive(Debug)]
pub struct Context {
    pub config: Config,

    // Channels
    pub errors_tx: Sender<ProjectError>,
    pub errors_rx: Receiver<ProjectError>,
}

impl Context {
    pub fn new(config: Config) -> Self {
        let (errors_tx, errors_rx) = crossbeam::channel::unbounded();

        Self {
            config,
            errors_tx,
            errors_rx,
        }
    }
}
