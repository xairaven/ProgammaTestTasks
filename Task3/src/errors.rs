use crate::logs::LogError;
use crate::parser::ParserError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Logger. {0}")]
    Logs(#[from] LogError),

    #[error("Parser. {0}")]
    Parser(#[from] ParserError),
}
