# Detection Rule: Exfiltration Over DNS Tunneling

Rule ID: **21890b79-0173-4afc-a46e-338635db2a75**

Rule Name: Exfiltration (T1048: Exfiltration Over Alternative Protocol)

MITRE ATT&CK Tactic: [Exfiltration](https://attack.mitre.org/tactics/TA0010/)

MITRE ATT&CK Technique: [T1048.003, Exfiltration Over Alternative Protocol: DNS](https://attack.mitre.org/techniques/T1048/003/)

## Description

This rule detects adversaries stealing data by transmitting it over the network. To evade security controls, attackers often use protocols that are different from their primary Command and Control (C2) channel.

A common covert technique is **DNS tunneling**, where stolen data is encoded into a large volume of unique DNS queries. Because DNS is a fundamental protocol that is almost always allowed through firewalls, it provides a stealthy channel for exfiltration. A more overt method, common on Linux, is to use standard file transfer utilities like `scp` (secure copy) to send data directly to an attacker-controlled machine.

## Rule Derivation from Log Analysis

The logic for these rules was developed by identifying the unique footprints of different exfiltration methods.

### **1. Defining the Behavior**:

- **DNS Tunneling (Windows)**: This behavior is a "DNS storm" from a single host, characterized by both a very high volume of total DNS queries and a high number of unique subdomains being queried.

- **Secure Copy (Ubuntu**): This behavior is the execution of the `scp` command with syntax indicating a file is being sent to a remote destination (i.e., `user@host`).

### **2. Translating Behavior to Log Fields**: 

- **Windows**: The detection uses DNS logs, grouping by the source host and counting both total queries and unique domains (`winlog.event_data.TargetDomainName`).

- **Ubuntu**: The detection uses process logs, inspecting the `process.name` and the `process.command_line` for specific patterns.

## Detection Logic

### Windows: DNS Tunneling

This is a threshold-based rule that triggers when the volume and variety of DNS queries from a single host exceed a defined limit within the rule's time window.

**Query**:

`event.category:network and event.dataset:dns`

**Threshold**:

- **Group By**: The rule groups DNS queries by the source host (`host.hostname.keyword` or `winlog.event_data.SourceIp.keyword`).

- **Condition 1 (Volume)**: The total number of DNS queries from a single host must be greater than or equal to 200.

- **Condition 2 (Variety)**: Within those queries, the number of unique domain names must be greater than or equal to 100.

**Query Explanation**:

The rule's logic is: "Alert if any single host makes more than 200 DNS queries to at least 100 different domain names within a five-minute window." This is a strong indicator of automated data exfiltration using DNS.

### Ubuntu: Exfiltration via scp

This query looks for the use of scp to copy files to a remote destination.

**Query**:

`process.name:"scp" and process.command_line:"*@*"`

**Explanation**: 

This query looks for any use of the `scp` command that includes the `user@host` syntax (indicated by the `@` symbol), which signifies that a file is being copied to a remote system.

## Simulation and Validation

### Windows

This rule can be validated by running a script that generates a high volume of DNS lookups for unique, non-existent subdomains.

**Test Command (PowerShell)**:

`1..200 | ForEach-Object { $subdomain = -join ((65..90) + (97..122) | Get-Random -Count 15 | ForEach-Object { [char]$_ }); try { Resolve-DnsName -Name "$subdomain.example.com" -ErrorAction SilentlyContinue } catch {} }`

This PowerShell one-liner runs a loop 200 times. In each iteration, it generates a random 15-character string to act as a unique subdomain and performs a DNS lookup for [random_string].example.com. This activity generates 200 DNS queries for 200 unique subdomains from a single host, which will satisfy both threshold conditions and trigger the alert.

### Ubuntu

This test simulates data exfiltration by using scp to send a file to a remote location (simulated using localhost).

**Test Command**:

**Step 1: Create a dummy file to exfiltrate**

`echo "secret stuff" > ~/exfil_this_file.txt`

**Step 2: Exfiltrate the file using scp**

`scp ~/exfil_this_file.txt $(whoami)@localhost:/tmp`

**Description**: 

This command uses `scp` with the `user@host` syntax (`$(whoami)@localhost`). This action simulates data being copied off the system and perfectly matches the rule's logic.
