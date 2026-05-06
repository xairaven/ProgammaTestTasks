use crate::parser::ParserError;
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct JournalEntry {
    pub timestamp: f64,
    pub uid: String,
    pub ip_source: Ipv4Addr,
    pub port_source: u16,
    pub ip_destination: Ipv4Addr,
    pub port_destination: u16,
    pub transaction_depth: u8,
    pub method: String, // TODO: Enum Structure
    pub host_header: Ipv4Addr,
    pub uri: String,
    pub referrer: Option<String>,
    pub user_agent: String,
    pub request_body_length: u16,
    pub response_body_length: u16,
    pub status_code: u16,
    pub status_message: String,
    pub info_code: Option<u16>,
    pub info_message: Option<String>,
    pub filename: Option<u16>,
    pub tags: Option<String>,
    pub username: Option<String>,
    pub password: Option<u16>,
    pub proxied: Option<String>,
    pub orig_fuids: Option<String>,
    pub orig_mime_types: Option<String>,
    pub resp_fuids: Option<String>,
    pub resp_mime_types: Option<String>,
}

impl JournalEntry {
    pub const FIELDS_AMOUNT: usize = 27;
}

impl TryFrom<(usize, &Vec<&str>)> for JournalEntry {
    type Error = ParserError;

    fn try_from(value: (usize, &Vec<&str>)) -> Result<Self, Self::Error> {
        const MINUS: &str = "-";
        const EMPTY: &str = "(empty)";

        let index = value.0 + 1;
        let arguments = value.1;

        let arguments_amount = arguments.len();
        if arguments_amount != Self::FIELDS_AMOUNT {
            return Err(Self::Error::NotEnoughArguments(
                index,
                arguments_amount,
                Self::FIELDS_AMOUNT,
            ));
        }

        let entry = Self {
            timestamp: arguments[0]
                .parse::<f64>()
                .map_err(|error| Self::Error::TimeStamp(index, error))?,
            uid: arguments[1].to_string(),
            ip_source: arguments[2]
                .parse::<Ipv4Addr>()
                .map_err(|error| Self::Error::IpSource(index, error))?,
            port_source: arguments[3]
                .parse::<u16>()
                .map_err(|error| Self::Error::PortSource(index, error))?,
            ip_destination: arguments[4]
                .parse::<Ipv4Addr>()
                .map_err(|error| Self::Error::IpDestination(index, error))?,
            port_destination: arguments[5]
                .parse::<u16>()
                .map_err(|error| Self::Error::PortDestination(index, error))?,
            transaction_depth: arguments[6]
                .parse::<u8>()
                .map_err(|error| Self::Error::TransactionDepth(index, error))?,
            method: arguments[7].to_string(),
            host_header: arguments[8]
                .parse::<Ipv4Addr>()
                .map_err(|error| Self::Error::HostHeader(index, error))?,
            uri: arguments[9].to_string(),
            referrer: match arguments[10] {
                MINUS | EMPTY => None,
                v => v.parse().ok(),
            },
            user_agent: arguments[11].to_string(),
            request_body_length: arguments[12]
                .parse::<u16>()
                .map_err(|error| Self::Error::RequestBodyLength(index, error))?,
            response_body_length: arguments[13]
                .parse::<u16>()
                .map_err(|error| Self::Error::ResponseBodyLength(index, error))?,
            status_code: arguments[14]
                .parse::<u16>()
                .map_err(|error| Self::Error::StatusCode(index, error))?,
            status_message: arguments[15].to_string(),
            info_code: match arguments[16] {
                MINUS | EMPTY => None,
                v => v
                    .parse::<u16>()
                    .map_err(|error| Self::Error::InfoCode(index, error))?
                    .into(),
            },
            info_message: match arguments[17] {
                MINUS | EMPTY => None,
                v => v.parse().ok(),
            },
            filename: match arguments[18] {
                MINUS | EMPTY => None,
                v => v
                    .parse::<u16>()
                    .map_err(|error| Self::Error::FileName(index, error))?
                    .into(),
            },
            tags: match arguments[19] {
                MINUS | EMPTY => None,
                v => v.parse().ok(),
            },
            username: match arguments[20] {
                MINUS | EMPTY => None,
                v => v.parse().ok(),
            },
            password: match arguments[18] {
                MINUS | EMPTY => None,
                v => v
                    .parse::<u16>()
                    .map_err(|error| Self::Error::Password(index, error))?
                    .into(),
            },
            proxied: match arguments[22] {
                MINUS | EMPTY => None,
                v => v.parse().ok(),
            },
            orig_fuids: match arguments[23] {
                MINUS | EMPTY => None,
                v => v.parse().ok(),
            },
            orig_mime_types: match arguments[24] {
                MINUS | EMPTY => None,
                v => v.parse().ok(),
            },
            resp_fuids: match arguments[25] {
                MINUS | EMPTY => None,
                v => v.parse().ok(),
            },
            resp_mime_types: match arguments[26] {
                MINUS | EMPTY => None,
                v => v.parse().ok(),
            },
        };

        Ok(entry)
    }
}
