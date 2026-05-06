use crate::cli::InputArgs;
use crate::errors::Error;
use crate::logic::entry::JournalEntry;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Default)]
pub struct Parser {
    pub separator: Separator,
    pub header: Option<String>,
}

impl Parser {
    pub fn parse(&self, args: InputArgs) -> Result<Vec<JournalEntry>, Error> {
        let file = File::open(&args.file).map_err(ParserError::FileOpen)?;
        log::info!("File opened.");

        let reader = BufReader::new(file);

        let mut entries = vec![];

        for (index, line_result) in reader.lines().enumerate() {
            let line = line_result.map_err(ParserError::LineParse)?;

            // Header
            if let Some(header) = &self.header
                && line.starts_with(header)
            {
                log::info!("Header found at line {}.", index + 1);
                continue;
            }

            let fields: Vec<&str> = line.split(self.separator.symbol()).collect();
            let entry = JournalEntry::try_from((index, &fields))?;
            entries.push(entry);
        }

        Ok(entries)
    }
}

#[derive(Debug, Default)]
pub enum Separator {
    Comma,
    Semicolon,
    #[default]
    Tab,
    Space,
}

impl Separator {
    pub fn symbol(&self) -> char {
        match self {
            Self::Comma => ',',
            Self::Semicolon => ';',
            Self::Tab => '\t',
            Self::Space => ' ',
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParserError {
    #[error("Failed to open file. {0}")]
    FileOpen(std::io::Error),

    #[error("Failed to parse line. {0}")]
    LineParse(std::io::Error),

    #[error("Not enough arguments on line {0}. Found: {1}, Needed: {2}")]
    NotEnoughArguments(usize, usize, usize),

    #[error("Failed to parse timestamp field on line {0}. {1}")]
    TimeStamp(usize, std::num::ParseFloatError),

    #[error("Failed to parse source IP on line {0}. {1}")]
    IpSource(usize, std::net::AddrParseError),

    #[error("Failed to parse source port on line {0}. {1}")]
    PortSource(usize, std::num::ParseIntError),

    #[error("Failed to parse destination IP on line {0}. {1}")]
    IpDestination(usize, std::net::AddrParseError),

    #[error("Failed to parse destination port on line {0}. {1}")]
    PortDestination(usize, std::num::ParseIntError),

    #[error("Failed to parse transaction depth on line {0}. {1}")]
    TransactionDepth(usize, std::num::ParseIntError),

    #[error("Failed to parse host (header) IP on line {0}. {1}")]
    HostHeader(usize, std::net::AddrParseError),

    #[error("Failed to parse request body length on line {0}. {1}")]
    RequestBodyLength(usize, std::num::ParseIntError),

    #[error("Failed to parse response body length on line {0}. {1}")]
    ResponseBodyLength(usize, std::num::ParseIntError),

    #[error("Failed to parse status code on line {0}. {1}")]
    StatusCode(usize, std::num::ParseIntError),

    #[error("Failed to parse info code on line {0}. {1}")]
    InfoCode(usize, std::num::ParseIntError),

    #[error("Failed to parse file name on line {0}. {1}")]
    FileName(usize, std::num::ParseIntError),

    #[error("Failed to parse password on line {0}. {1}")]
    Password(usize, std::num::ParseIntError),
}
