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

    pub fn print_schema_report(entries: &[JournalEntry]) {
        use std::collections::HashSet;

        println!(
            "{:<20} | {:<10} | {:<10} | {:<15} | {:<15}",
            "Data Type", "Type", "Count", "Unique Values", "Missing Values"
        );
        println!("{:-<78}", "");

        let total = entries.len();

        // Macro for necessary fields
        macro_rules! count_req {
            ($name:expr, $type_str:expr, $field:ident, $transform:expr) => {
                let mut unique = HashSet::new();
                for e in entries {
                    unique.insert($transform(&e.$field));
                }
                println!(
                    "{:<20} | {:<10} | {:<10} | {:<15} | {:<15}",
                    $name,
                    $type_str,
                    total,
                    unique.len(),
                    0
                );
            };
        }

        // Macro for optional fields (With missing values)
        macro_rules! count_opt {
            ($name:expr, $type_str:expr, $field:ident, $transform:expr) => {
                let mut unique = HashSet::new();
                let mut missing = 0;
                for e in entries {
                    if let Some(val) = &e.$field {
                        unique.insert($transform(val));
                    } else {
                        missing += 1;
                    }
                }
                let present = total - missing;
                println!(
                    "{:<20} | {:<10} | {:<10} | {:<15} | {:<15}",
                    $name,
                    $type_str,
                    present,
                    unique.len(),
                    missing
                );
            };
        }

        // Generating table
        // For f64 we are using to_bits() because f64 is not implementing Hash
        count_req!("ts", "float64", timestamp, |v: &f64| v.to_bits());
        count_req!("uid", "object", uid, |v| v);
        count_req!("id.orig_h", "object", ip_source, |v| v);
        count_req!("id.orig_p", "int64", port_source, |v| v);
        count_req!("id.resp_h", "object", ip_destination, |v| v);
        count_req!("id.resp_p", "int64", port_destination, |v| v);
        count_req!("trans_depth", "int64", transaction_depth, |v| v);

        count_opt!("method", "object", method, |v| v);
        count_req!("host", "object", host_header, |v| v);
        count_req!("uri", "object", uri, |v| v);
        count_opt!("referrer", "object", referrer, |v| v);
        count_req!("user_agent", "object", user_agent, |v| v);

        count_req!("request_body_len", "int64", request_body_length, |v| v);
        count_req!("response_body_len", "int64", response_body_length, |v| v);

        count_opt!("status_code", "float64", status_code, |v| v);
        count_opt!("status_msg", "object", status_message, |v| v);
        count_opt!("info_code", "float64", info_code, |v| v);
        count_opt!("info_msg", "object", info_message, |v| v);
        count_opt!("filename", "object", filename, |v| v);
        count_opt!("tags", "object", tags, |v| v);
        count_opt!("username", "object", username, |v| v);
        count_opt!("password", "object", password, |v| v);
        count_opt!("proxied", "object", proxied, |v| v);
        count_opt!("orig_fuids", "object", orig_fuids, |v| v);
        count_opt!("orig_mime_types", "object", orig_mime_types, |v| v);
        count_opt!("resp_fuids", "object", resp_fuids, |v| v);
        count_opt!("resp_mime_types", "object", resp_mime_types, |v| v);
    }
}
