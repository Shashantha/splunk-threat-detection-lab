# Splunk Threat Detection Lab (Splunk 10.0.1)

Real-time threat detection and purple-team adversary simulation lab hosted on **Kali Linux** (`Splunk Enterprise 10.0.1`), ingesting telemetry from **Windows 11** and **Windows Server 2022 Core** endpoints[cite: 1, 8].

## Lab Architecture
- **SIEM Indexer & Search Head:** Splunk Enterprise 10.0.1 on Kali Linux (TCP `9997` Splunk-to-Splunk receiver, UDP `514` Syslog)[cite: 4, 8]
- **Monitored Endpoints:** Windows Server 2022 Core & Windows 11 via Splunk Universal Forwarder (`renderXml = true`)[cite: 1, 3, 4, 8]
- **Virtualization:** VMware Workstation isolated host-only network[cite: 1, 2]

## Detection Rules & Adversary Simulation Matrix

| Detection Rule | Attack Simulation (Kali Linux) | Telemetry & Event IDs | MITRE ATT&CK |
| :--- | :--- | :--- | :--- |
| **Suspicious Remote Service Creation** | Impacket `psexec` / `smbexec` lateral movement[cite: 3] | Event ID `4624` + `7045` (XML `rex` extraction flagging `cmd.exe`/`powershell` paths)[cite: 1, 3] | T1543.003 |
| **Remote Thread / Process Injection** | Cross-process memory injection testing | Sysmon Event ID `8` (`CreateRemoteThread`)[cite: 1] | T1055 |
| **High-Volume Failed Logons** | `netexec smb` / Hydra brute-force password spraying[cite: 3] | Event ID `4625` (`count > 5` per source IP)[cite: 1, 3] | T1110 |
| **Backdoor Local Admin Creation** | `net user` / `net localgroup Administrators`[cite: 3] | Event ID `4720` & `4732`[cite: 3] | T1136.001 |
| **Network Port Reconnaissance** | `nmap -sS` stealth SYN scan[cite: 3] | Windows Filtering Platform Event ID `5157`[cite: 3] | T1046 |

## Repository Structure
- `splunk-configs/` — Exported SPL correlation alerts (`savedsearches.conf`), XML `rex` field extractions, and views
- `forwarder-configs/` — Windows Universal Forwarder `inputs.conf` configured for XML event rendering[cite: 4]
- `screenshots/` — Splunk Web alert triggers and triage evidence
