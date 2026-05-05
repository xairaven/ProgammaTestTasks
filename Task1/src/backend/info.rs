use crate::ui::errors::FrontendError;
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct InitialInformation {
    pub attacker_ip: Ipv4Addr,
    pub file: PathBuf,
}

impl InitialInformation {
    pub fn new(ip: String, file: PathBuf) -> Result<Self, FrontendError> {
        let address = ip
            .parse::<Ipv4Addr>()
            .map_err(|_| FrontendError::InvalidIp(ip))?;

        Ok(Self {
            attacker_ip: address,
            file,
        })
    }
}
