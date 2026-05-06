use crate::backend::errors::BackendError;
use crate::backend::info::{InfectedHostInfo, InitialInformation, NetworkDevice};
use crate::commands::{EngineEvent, UiCommand};
use crate::errors::ProjectError;
use crossbeam::channel::{Receiver, Sender, TryRecvError};
use rtshark::{Layer, Packet, RTSharkBuilder};

#[derive(Debug)]
pub struct Engine {
    // Channels
    pub ui_command_rx: Receiver<UiCommand>,
    pub engine_event_tx: Sender<EngineEvent>,
    pub errors_tx: Sender<ProjectError>,
}

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
                Err(TryRecvError::Empty) => continue,
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

        let mut rtshark = RTSharkBuilder::builder()
            .input_path(path)
            .spawn()
            .map_err(BackendError::TSharkInitialize)?;

        let mut full_infos = vec![];
        let mut infected_devices = vec![];

        loop {
            let packet = rtshark.read().map_err(BackendError::PacketRead)?;

            let packet = match packet {
                Some(packet) => packet,
                None => break,
            };

            // First stage: checking, if this exact packet gives info about infected machine
            if let Some(device) = Self::is_talking_to_attacker(&attacker_ip, &packet) {
                infected_devices.push(device);
            }

            // Anyway, maybe that's the packet that involves other infected machines. So:
            // Stage 2: Are there involved infected machines?
            let involved_infected_machines = infected_devices
                .iter()
                .filter(|device| Self::is_packet_involves_victim(device, &packet))
                .cloned()
                .collect::<Vec<_>>();

            if involved_infected_machines.is_empty() {
                continue;
            }

            let mut full_info_involved = involved_infected_machines
                .into_iter()
                .map(|device| InfectedHostInfo {
                    ip: Some(device.ip),
                    mac: device.mac,
                    hostname: None,
                    sam_account_name: None,
                    display_name: None,
                })
                .collect::<Vec<_>>();

            // Stage 3: If yes, searching for names
            for layer in packet {
                // Firstly, trying to get Hostname from NetLogon or NBNS
                if let Some(hostname) = Self::hostname(&layer) {
                    for info in &mut full_info_involved {
                        if info.hostname.is_none() {
                            info.hostname = Some(hostname.clone());
                        }
                    }
                }

                // Secondly -- trying to get sAMAccountName (from Kerberos AS-REQ)
                if let Some(account_name) = Self::account_name(&layer) {
                    for info in &mut full_info_involved {
                        if info.sam_account_name.is_none() {
                            info.sam_account_name = Some(account_name.clone());
                        }
                    }
                }

                // Finally -- getting Display Name from SAMR
                if let Some(display_name) = Self::display_name(&layer) {
                    for info in &mut full_info_involved {
                        if info.display_name.is_none() {
                            info.display_name = Some(display_name.clone());
                        }
                    }
                }
            }

            full_infos.extend(full_info_involved);
        }

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

    fn is_packet_involves_victim(device: &NetworkDevice, packet: &Packet) -> bool {
        let packet = packet.clone();

        for layer in packet {
            if layer.name() == IP_LAYER_IDENTIFIER {
                if let Some(src) = layer.metadata(IP_SOURCE_METADATA)
                    && src.value() == device.ip
                {
                    return true;
                }

                if let Some(dst) = layer.metadata(IP_DESTINATION_METADATA)
                    && dst.value() == device.ip
                {
                    return true;
                }
            }
        }

        false
    }

    fn hostname(layer: &Layer) -> Option<String> {
        const NETLOGON: &str = "netlogon";
        const NETLOGON_COMPUTER_NAME: &str = "netlogon.computer_name";
        const NBNS: &str = "nbns";
        const NBNS_NAME: &str = "nbns.name";

        if layer.name() == NETLOGON
            && let Some(host) = layer.metadata(NETLOGON_COMPUTER_NAME)
        {
            Some(host.value().to_string())
        } else if layer.name() == NBNS
            && let Some(nbns_name) = layer.metadata(NBNS_NAME)
        {
            let name = nbns_name.value().to_string();
            if name.contains("DESKTOP") {
                // Cleaning from suffices like <00>>
                let clean_name = name.split('<').next().unwrap_or(&name).trim();
                return Some(clean_name.to_string());
            }
            None
        } else {
            None
        }
    }

    fn account_name(layer: &Layer) -> Option<String> {
        const KERBEROS: &str = "kerberos";
        const KERBEROS_NAME_METADATA: &str = "kerberos.name_string";

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
        const SAMR_NAME_METADATA: &str = "samr.full_name";

        if layer.name() == SAMR
            && let Some(full_name) = layer.metadata(SAMR_NAME_METADATA)
        {
            let name = full_name.value().to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }

        None
    }
}
