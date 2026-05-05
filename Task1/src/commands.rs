use crate::backend::info::InitialInformation;

#[derive(Debug)]
pub enum UiCommand {
    Start(InitialInformation),
    Exit,
}

#[derive(Debug)]
pub enum EngineEvent {}
