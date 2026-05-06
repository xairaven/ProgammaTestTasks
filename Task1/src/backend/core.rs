use crate::backend::errors::BackendError;
use crate::backend::info::{InfectedHostInfo, InitialInformation, NetworkDevice};
use crate::commands::{EngineEvent, UiCommand};
use crate::errors::ProjectError;
use crossbeam::channel::{Receiver, Sender, TryRecvError};
use rtshark::{Layer, Packet, RTSharkBuilder};
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

#[derive(Debug)]
pub struct Engine {
    // Channels
    pub ui_command_rx: Receiver<UiCommand>,
    pub engine_event_tx: Sender<EngineEvent>,
    pub errors_tx: Sender<ProjectError>,
}

const UPDATE_LOGS_EVERY_X_PACKAGES: u16 = 100;

const ETHERNET_LAYER_IDENTIFIER: &str = "eth";

const ETHERNET_SOURCE_METADATA: &str = "eth.src";
const IP_LAYER_IDENTIFIER: &str = "ip";
const IP_DESTINATION_METADATA: &str = "ip.dst";
const IP_SOURCE_METADATA: &str = "ip.src";

impl Engine {
    pub fn run(&mut self) {
        loop {
            let command = match self.ui_command_rx.try_recv() {
                Ok(value) => value,
                Err(TryRecvError::Disconnected) => return,
                Err(TryRecvError::Empty) => {
                    thread::sleep(Duration::from_millis(500));
                    continue;
                },
            };

            let result = match command {
                UiCommand::Start(info) => self.analyze(info),
                UiCommand::Exit => return,
            };

            match result {
                Ok(infos) => {
                    for info in infos {
                        let event = EngineEvent::PassInfo(info);
                        let _ = self.engine_event_tx.try_send(event);
                    }
                },
                Err(error) => {
                    let _ = self.errors_tx.try_send(error);
                },
            }
        }
    }

    fn analyze(
        &self, info: InitialInformation,
    ) -> Result<Vec<InfectedHostInfo>, ProjectError> {
        let path = info.file.to_str().ok_or(BackendError::InvalidPath)?;
        let attacker_ip = info.attacker_ip.to_string();

        let tshark_filter = format!(
            "ip.addr == {} or ldap or cldap or nbns or llmnr or kerberos or samr or dcerpc or smb2",
            attacker_ip
        );

        // Using Hashmap for avoiding duplicates. Key -- Victim IP
        let mut infected_hosts: HashMap<String, InfectedHostInfo> = HashMap::new();

        // FIRST PASS
        let mut rtshark = RTSharkBuilder::builder()
            .input_path(path)
            .display_filter(&tshark_filter)
            .spawn()
            .map_err(BackendError::TSharkInitialize)?;
        self.send_progress("Started analysis. First pass");
        let mut packet_index = 1;
        while let Some(packet) = rtshark.read().map_err(BackendError::PacketRead)? {
            if packet_index % UPDATE_LOGS_EVERY_X_PACKAGES == 0 {
                self.send_progress(&format!("(1) Analyzing packet #{}", packet_index));
            }
            // First stage: checking, if this exact packet gives info about infected machine
            if let Some(device) = Self::is_talking_to_attacker(&attacker_ip, &packet) {
                infected_hosts.entry(device.ip.clone()).or_insert_with(|| {
                    InfectedHostInfo {
                        ip: Some(device.ip.clone()),
                        mac: device.mac.clone(),
                        hostname: None,
                        sam_account_name: None,
                        display_name: None,
                    }
                });
            }
            packet_index += 1;
        }

        // SECOND PASS
        let mut rtshark = RTSharkBuilder::builder()
            .input_path(path)
            .display_filter(&tshark_filter)
            .spawn()
            .map_err(BackendError::TSharkInitialize)?;
        self.send_progress("\nStarted analysis. Second pass");
        let mut packet_index = 1;
        while let Some(packet) = rtshark.read().map_err(BackendError::PacketRead)? {
            if packet_index % UPDATE_LOGS_EVERY_X_PACKAGES == 0 {
                self.send_progress(&format!("(2) Analyzing packet #{}", packet_index));
            }

            // Stage 2: Is packet involves victims?
            let mut involved_victim_ip = None;
            for layer in packet.clone() {
                if layer.name() == IP_LAYER_IDENTIFIER {
                    if let Some(src) = layer.metadata(IP_SOURCE_METADATA)
                        && infected_hosts.contains_key(src.value())
                    {
                        involved_victim_ip = Some(src.value().to_string());
                        break;
                    }
                    if let Some(dst) = layer.metadata(IP_DESTINATION_METADATA)
                        && infected_hosts.contains_key(dst.value())
                    {
                        involved_victim_ip = Some(dst.value().to_string());
                        break;
                    }
                }
            }

            // Stage 3: If packet is "owned" by some victim, searching for name and updating profile
            if let Some(victim_ip) = involved_victim_ip
                && let Some(host_info) = infected_hosts.get_mut(&victim_ip)
            {
                for layer in packet {
                    if host_info.hostname.is_none()
                        && let Some(hostname) = Self::hostname(&layer)
                    {
                        host_info.hostname = Some(hostname);
                    }

                    if host_info.sam_account_name.is_none()
                        && let Some(account_name) = Self::account_name(&layer)
                    {
                        host_info.sam_account_name = Some(account_name);
                    }

                    if host_info.display_name.is_none()
                        && let Some(display_name) = Self::display_name(&layer)
                    {
                        host_info.display_name = Some(display_name);
                    }
                }
            }

            packet_index += 1;
        }

        let full_infos: Vec<InfectedHostInfo> = infected_hosts.into_values().collect();

        Ok(full_infos)
    }

    fn is_talking_to_attacker(attacker: &str, packet: &Packet) -> Option<NetworkDevice> {
        let packet = packet.clone();
        let layers = packet.layers();

        let mut is_for_attacker = false;
        let mut result = None;

        for layer in layers.iter().rev() {
            if layer.name() == IP_LAYER_IDENTIFIER {
                if let Some(destination) = layer.metadata(IP_DESTINATION_METADATA)
                    && destination.value() == attacker
                {
                    is_for_attacker = true;
                }

                if is_for_attacker && let Some(src) = layer.metadata(IP_SOURCE_METADATA) {
                    let device = NetworkDevice::with_ip(src.value().to_string());
                    result = Some(device);
                }
            }

            if is_for_attacker
                && layer.name() == ETHERNET_LAYER_IDENTIFIER
                && let Some(mac) = layer.metadata(ETHERNET_SOURCE_METADATA)
                && let Some(device) = &mut result
            {
                device.set_mac(mac.value().to_string());
            }
        }

        result
    }

    fn hostname(layer: &Layer) -> Option<String> {
        const NBNS: &str = "nbns";
        const NBNS_NAME: &str = "nbns.name";
        const LDAP: &str = "ldap";
        const LLMNR: &str = "llmnr";
        const LLMNR_NAME: &str = "dns.qry.name";

        if layer.name() == NBNS
            && let Some(nbns_name) = layer.metadata(NBNS_NAME)
        {
            let name = nbns_name.display().unwrap_or_else(|| nbns_name.value());

            // Clean XML entities (&lt;) and NetBIOS suffixes (<00>)
            let clean_name = name
                .split('<')
                .next()
                .unwrap_or(name)
                .split("&lt;")
                .next()
                .unwrap_or(name)
                .trim()
                .replace("Name: ", "");

            // Filter out empty strings and standard system group names
            if !clean_name.is_empty()
                && clean_name != "WORKGROUP"
                && clean_name != "LOCAL"
                && !clean_name.starts_with("__MSBROWSE__")
            {
                return Some(clean_name.to_string());
            }
        }

        if layer.name() == LDAP {
            for meta in layer.iter() {
                let val = meta.value();
                if val.contains("(Host=")
                    && let Some(start) = val.find("Host=")
                {
                    let start_idx = start + 5;
                    if let Some(end) = val[start_idx..].find(')') {
                        return Some(val[start_idx..start_idx + end].to_string());
                    }
                }
            }
        }

        if layer.name() == LLMNR {
            for meta in layer.iter() {
                if meta.name() == LLMNR_NAME {
                    return Some(meta.value().to_string());
                }
            }
        }

        None
    }

    fn account_name(layer: &Layer) -> Option<String> {
        const KERBEROS: &str = "kerberos";
        const KERBEROS_NAME_METADATA: &str = "kerberos.CNameString";

        if layer.name() == KERBEROS
            && let Some(cname) = layer.metadata(KERBEROS_NAME_METADATA)
        {
            let name = cname.value().to_string();
            // Filtering service names from Windows itself
            if name != "krbtgt" && name != "cifs" && name != "host" {
                return Some(name);
            }
        }

        None
    }

    fn display_name(layer: &Layer) -> Option<String> {
        const SAMR: &str = "samr";
        const SAMR_NAME_METADATA: &str = "samr.samr_UserInfo21.full_name";

        if layer.name() == SAMR {
            for meta in layer.iter() {
                if meta.name() == SAMR_NAME_METADATA {
                    let mut name = meta.value().to_string();
                    if name.is_empty() {
                        name = meta.display().unwrap_or("").to_string();
                    }
                    if !name.is_empty() {
                        return Some(name);
                    }
                }
            }
        }

        None
    }

    fn send_progress(&self, message: &str) {
        let _ = self
            .engine_event_tx
            .send(EngineEvent::PassProgress(message.to_string()));
    }
}
