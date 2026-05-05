use thiserror::Error;

#[derive(Debug, Error)]
pub enum FrontendError {
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    #[error("There's no .pcap file loaded. Please load a .pcap file to proceed.")]
    NoFile,
}
