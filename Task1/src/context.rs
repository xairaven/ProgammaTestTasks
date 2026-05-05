use crate::backend::core::Engine;
use crate::commands::{EngineEvent, UiCommand};
use crate::config::Config;
use crate::errors::ProjectError;
use crossbeam::channel::{Receiver, Sender};

#[derive(Debug)]
pub struct Context {
    // Channels
    pub output_tx: Sender<String>,
    pub output_rx: Receiver<String>,

    pub ui_command_tx: Sender<UiCommand>,
    pub ui_command_rx: Receiver<UiCommand>,

    pub engine_event_tx: Sender<EngineEvent>,
    pub engine_event_rx: Receiver<EngineEvent>,

    pub errors_tx: Sender<ProjectError>,
    pub errors_rx: Receiver<ProjectError>,
}

impl Context {
    pub fn new(_config: Config) -> Self {
        let (errors_tx, errors_rx) = crossbeam::channel::unbounded();
        let (output_tx, output_rx) = crossbeam::channel::unbounded();
        let (engine_event_tx, engine_event_rx) = crossbeam::channel::unbounded();
        let (ui_command_tx, ui_command_rx) = crossbeam::channel::unbounded();

        let mut engine = Engine {
            ui_command_rx: ui_command_rx.clone(),
            engine_event_tx: engine_event_tx.clone(),
            errors_tx: errors_tx.clone(),
        };

        std::thread::spawn(move || {
            engine.run();
        });

        Self {
            errors_tx,
            errors_rx,

            output_tx,
            output_rx,

            ui_command_tx,
            ui_command_rx,

            engine_event_tx,
            engine_event_rx,
        }
    }
}
