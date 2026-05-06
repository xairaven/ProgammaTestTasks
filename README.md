# ProGamma Agency. Technical Assignments Repository

**Field**: Rust & Cybersecurity

This repository contains solutions for three technical tasks covering network traffic analysis, 
cryptographic operations, and event log processing.

The project structure is organized as a *Cargo workspace*. 
The [*tasks*](./tasks) folder contains the initial task descriptions and requirements 
without the target files. The solution for each task is implemented 
as a separate Rust crate within the [*Task1*](./Task1), [*Task2*](./Task2), and Task3 directories. 
All accompanying documentation, including reports, screenshots, and analytical notes, 
is located in the [*docs*](./docs) directory.

*Task1* includes a Rust utility for the automated extraction of network artifacts 
from PCAP files, alongside a detailed incident report. 
The program identifies signs of NetSupport Manager activity, 
extracting the victim's IP and MAC addresses, hostname, sAMAccountName, and display name.

- **Manual Search Report**: [*Markdown file*](./docs/Task1/ManualSearch.md)
- **Automated Search Report**: [*Markdown file*](./docs/Task1/Automated.md)

*Task2* contains the implementation of a bitwise XOR function for input data in binary, 
octal, or hexadecimal numeral systems. The utility correctly processes the buffers of 
equal length and returns the result in the original format.

- **Explanation**: [*Markdown file*](./docs/Task2/Explanation.md)

*Task3* is a CLI tool for parsing HTTP logs. The utility aggregates connection 
statistics and performs a search for suspicious network activity, helping to identify 
potential threats in the network traffic.

In addition to the source code, several analytical artifacts are required and provided in 
the documentation folder. For the first task, a formal report for the Incident Response team 
is prepared to facilitate the quick isolation of the compromised machine. 
The [*docs/Task1*](./docs/Task1) directory contains Wireshark screenshots confirming 
the found artifacts and a step-by-step explanation of the manual analysis process. 
For the third task, a mini-research of the HTTP logs is conducted. The conclusions regarding any 
found anomalies or attack traces, along with justifications for why specific activity is 
considered suspicious and examples of the statistics output, are stored in the docs/Task3 directory.