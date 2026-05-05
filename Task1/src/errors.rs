use crate::backend::errors::BackendError;
use crate::config::ConfigError;
use crate::logger::LoggerError;
use crate::ui::GraphicsBackendError;
use crate::ui::errors::FrontendError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("Configuration. {0}")]
    Config(#[from] ConfigError),

    #[error("Graphics Backend. {0}")]
    GraphicsBackend(#[from] GraphicsBackendError),

    #[error("Logger. {0}")]
    Logger(#[from] LoggerError),

    #[error("User Input. {0}")]
    Frontend(#[from] FrontendError),

    #[error("Backend. {0}")]
    Backend(#[from] BackendError),
}
