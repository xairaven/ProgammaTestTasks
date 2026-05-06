use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("Invalid file path to .pcap file.")]
    InvalidPath,

    #[error("TShark initialization. {0}")]
    TSharkInitialize(io::Error),

    #[error("Packet read. {0}")]
    PacketRead(io::Error),
}
