use crate::cli::InputArgs;
use crate::logs::Logger;
use clap::Parser;

fn main() {
    let args = InputArgs::parse();

    Logger::from_args(&args).setup().unwrap_or_else(|error| {
        eprintln!("Error: {}", error);
        std::process::exit(1);
    });

    let entries = parser::Parser::default()
        .parse(args)
        .unwrap_or_else(|error| {
            eprintln!("Error: {}", error);
            std::process::exit(1);
        });
}

mod cli;
mod errors;
mod logs;
mod parser;

mod logic {
    pub mod entry;
}
