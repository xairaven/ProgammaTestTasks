use clap::Parser;
use log::LevelFilter;
use std::path::PathBuf;

#[derive(Parser)]
pub struct InputArgs {
    #[arg(short, long, help = "Path to the journal file.")]
    pub file: PathBuf,

    #[arg(
        short,
        long,
        value_enum,
        default_value = "off",
        help = "Set the logging level (off, error, warn, info, debug, trace)"
    )]
    pub log_level: LevelFilter,
}
