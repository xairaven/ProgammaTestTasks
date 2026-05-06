use crate::cli::InputArgs;
use crate::logic::analyzer::Analyzer;
use crate::logs::Logger;
use clap::Parser;

fn main() {
    let args = InputArgs::parse();

    Logger::from_args(&args).setup().unwrap_or_else(|error| {
        eprintln!("Error: {}", error);
        std::process::exit(1);
    });

    let entries = parser::Parser::default()
        .parse(&args)
        .unwrap_or_else(|error| {
            eprintln!("Error: {}", error);
            std::process::exit(1);
        });

    println!("Parsing finished. Analyzing {} records...", entries.len());

    if args.schema_report {
        Analyzer::print_schema_report(&entries);
        return;
    }

    let report = Analyzer::analyze(&entries);

    println!("\n=== GENERAL STATISTICS ===");
    println!("Total HTTP Requests: {}", report.total_requests);
    println!("Unique Source IPs: {}", report.ip_stats.len());

    println!("\nTop HTTP Methods:");
    let mut methods: Vec<_> = report.methods_stat.into_iter().collect();
    methods.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (method, count) in methods.into_iter().take(5) {
        println!("  {}: {}", method, count);
    }

    println!("\n=== BEHAVIORAL ANOMALIES (BRUTE-FORCE) ===");
    for (ip, stat) in &report.ip_stats {
        // If IP made more than 100 requests and 80% -- 404 errors, that's bruteforce
        if stat.total_requests > 100
            && (stat.not_found_404 as f64 / stat.total_requests as f64) > 0.8
        {
            println!(
                "[!] WARNING: IP {} is likely brute-forcing directories ({} errors 404 / {} total requests)",
                ip, stat.not_found_404, stat.total_requests
            );
        }
        // Password bruteforce
        if stat.forbidden_401_403 > 50 {
            println!(
                "[!] WARNING: IP {} might be brute-forcing passwords ({} 401/403 errors)",
                ip, stat.forbidden_401_403
            );
        }
    }

    println!("\n=== SIGNATURE DETECTIONS ===");
    println!(
        "Found {} specific suspicious requests.",
        report.suspicious_events.len()
    );
    // First five, for example
    for event in report.suspicious_events.iter().take(5) {
        println!(
            "Line {}: [{}] IP {} -> {}",
            event.line_index, event.category, event.ip, event.details
        );
    }
}

mod cli;
mod errors;
mod logs;
mod parser;

mod logic {
    pub mod analyzer;
    pub mod entry;
}
