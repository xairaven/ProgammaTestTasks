use crate::logic::entry::{HTTPMethod, JournalEntry};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Default, Debug)]
pub struct AnalyzerReport {
    pub total_requests: usize,
    pub methods_stat: HashMap<HTTPMethod, usize>,
    pub status_codes_stat: HashMap<u16, usize>,
    pub ip_stats: HashMap<IpAddr, IpActivity>,
    pub suspicious_events: Vec<SuspiciousEvent>,
}

#[derive(Default, Debug)]
pub struct IpActivity {
    pub total_requests: usize,
    pub not_found_404: usize,
    pub forbidden_401_403: usize,
}

#[derive(Debug)]
pub struct SuspiciousEvent {
    pub line_index: usize,
    pub ip: IpAddr,
    pub category: String,
    pub details: String,
}

pub struct Analyzer;

impl Analyzer {
    pub fn analyze(entries: &[JournalEntry]) -> AnalyzerReport {
        let mut report = AnalyzerReport {
            total_requests: entries.len(),
            ..Default::default()
        };

        for (index, entry) in entries.iter().enumerate() {
            // Main stats
            if let Some(method) = &entry.method {
                *report.methods_stat.entry(method.clone()).or_insert(0) += 1;
            }

            if let Some(code) = entry.status_code {
                *report.status_codes_stat.entry(code).or_insert(0) += 1;
            }

            // Stats by IPs
            let ip_stat = report.ip_stats.entry(entry.ip_source).or_default();
            ip_stat.total_requests += 1;

            match entry.status_code {
                Some(404) => ip_stat.not_found_404 += 1,
                Some(401) | Some(403) => ip_stat.forbidden_401_403 += 1,
                _ => {},
            }

            // Searching by signature
            Self::check_suspicious_activity(index, entry, &mut report.suspicious_events);
        }

        report
    }

    fn check_suspicious_activity(
        index: usize, entry: &JournalEntry, events: &mut Vec<SuspiciousEvent>,
    ) {
        let ua_lower = entry.user_agent.to_lowercase();
        let uri_lower = entry.uri.to_lowercase();

        // Scanning user agents for some scanners
        let scanners = ["nmap", "sqlmap", "dirbuster", "nikto", "masscan", "zgrab"];
        if scanners.iter().any(|&scanner| ua_lower.contains(scanner)) {
            events.push(SuspiciousEvent {
                line_index: index + 1,
                ip: entry.ip_source,
                category: "Scanner Detected".to_string(),
                details: format!("Malicious User-Agent: {}", entry.user_agent),
            });
        }

        // Path Traversal, SQLs
        let malicious_payloads = [
            "../",
            "..%2f",
            "%2e%2e", // Path Traversal
            "/etc/passwd",
            "cmd.exe",
            ".env",
            ".git/", // LFI / Sensitive Files
            "union%20select",
            "%27%20or%20", // SQLs
        ];

        if malicious_payloads
            .iter()
            .any(|&payload| uri_lower.contains(payload))
        {
            events.push(SuspiciousEvent {
                line_index: index + 1,
                ip: entry.ip_source,
                category: "Exploit Attempt".to_string(),
                details: format!("Suspicious URI: {}", entry.uri),
            });
        }
    }
}
