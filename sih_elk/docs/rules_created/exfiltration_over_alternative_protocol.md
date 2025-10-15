# Detection Rule: Exfiltration Over DNS Tunneling

Rule ID: **21890b79-0173-4afc-a46e-338635db2a75**

Rule Name: Exfiltration (T1048: Exfiltration Over Alternative Protocol)

MITRE ATT&CK Tactic: [Exfiltration](https://attack.mitre.org/tactics/TA0010/)

MITRE ATT&CK Technique: [T1048.003, Exfiltration Over Alternative Protocol: DNS](https://attack.mitre.org/techniques/T1048/003/)

## Description

Data is often stolen by transmitting it over a protocol that differs from the primary C2 channel. This rule detects **DNS tunneling**, a technique where an attacker encodes stolen data into a series of DNS queries.

Because DNS is a fundamental network protocol and is almost always allowed through firewalls, it provides a covert channel for exfiltration. A compromised host will make an abnormally high number of DNS requests to many unique, malicious subdomains. Each query's subdomain contains a small chunk of the stolen data. This rule identifies this **"DNS storm"** behavior.

## Rule Derivation from Log Analysis

The logic for this rule was developed by establishing a baseline for normal DNS activity and identifying the statistical anomalies created by DNS tunneling.

### **1. Defining the Behavior**:

DNS tunneling is characterized by two main factors from a single host: a very high volume of total DNS queries and a high cardinality (uniqueness) of the domains being queried. Legitimate activity may be high volume (e.g., loading a website), but the number of unique domains is typically limited. Tunneling creates hundreds of unique subdomains.

### **2. Translating Behavior to Log Fields**: 

This behavior is observed in DNS logs (`event.dataset:dns`). The key fields are the source of the query (`host.hostname`) and the domain being queried (`winlog.event_data.TargetDomainName.keyword`).

### **3. Constructing the Rule**: 

A simple query is insufficient. A **threshold rule** was built to group events by the source host. The rule then requires two conditions to be met: the total count of DNS queries from that host must exceed a high threshold (200), and the number of unique domains within those queries must also exceed a high threshold (100). This dual condition effectively isolates the unique pattern of DNS tunneling.

## Detection Logic

This is a threshold-based rule that triggers when the volume and variety of DNS queries from a single host exceed a defined limit within the rule's time window.

### Query:

`event.category:network and event.dataset:dns`


### Threshold:

- **Group By**: The rule groups DNS queries by the source host (`host.hostname.keyword` or `winlog.event_data.SourceIp.keyword`).

- **Condition 1 (Volume)**: The total number of DNS queries from a single host must be greater than or equal to 200.

- **Condition 2 (Variety)**: Within those queries, the number of unique domain names must be greater than or equal to 100.

### Query Explanation:

The rule's logic is: "Alert if any single host makes more than 200 DNS queries to at least 100 different domain names within a five-minute window." This is a strong indicator of automated data exfiltration using DNS.

## Simulation and Validation

This rule can be validated by running a script that generates a high volume of DNS lookups for unique, non-existent subdomains.

### Atomic Red Team Test Command:

`1..200 | ForEach-Object { $subdomain = -join ((65..90) + (97..122) | Get-Random -Count 15 | ForEach-Object { [char]$_ }); try { Resolve-DnsName -Name "$subdomain.example.com" -ErrorAction SilentlyContinue } catch {} }`

This PowerShell one-liner runs a loop 200 times. In each iteration, it generates a random 15-character string to act as a unique subdomain and performs a DNS lookup for [random_string].example.com. This activity generates 200 DNS queries for 200 unique subdomains from a single host, which will satisfy both threshold conditions and trigger the alert.

