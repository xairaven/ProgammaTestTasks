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

#[derive(Debug, Clone)]
pub struct NetworkDevice {
    pub ip: String,
    pub mac: Option<String>,
}

impl NetworkDevice {
    pub fn with_ip(ip: String) -> Self {
        Self { ip, mac: None }
    }

    pub fn set_mac(&mut self, mac: String) {
        self.mac = Some(mac);
    }
}

#[derive(Debug, Default)]
pub struct InfectedHostInfo {
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub sam_account_name: Option<String>,
    pub display_name: Option<String>,
}

impl std::fmt::Display for InfectedHostInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut result = String::from("Infected Host Information:\n");

        result.push_str(&format!(
            "IP Address: {}\n",
            self.ip.as_deref().unwrap_or("N/A")
        ));
        result.push_str(&format!(
            "MAC Address: {}\n",
            self.mac.as_deref().unwrap_or("N/A")
        ));
        result.push_str(&format!(
            "Host: {}\n",
            self.hostname.as_deref().unwrap_or("N/A")
        ));
        result.push_str(&format!(
            "sAMAccountName: {}\n",
            self.sam_account_name.as_deref().unwrap_or("N/A")
        ));
        result.push_str(&format!(
            "Full Name: {}\n",
            self.display_name.as_deref().unwrap_or("N/A")
        ));

        write!(f, "{}", result)
    }
}
