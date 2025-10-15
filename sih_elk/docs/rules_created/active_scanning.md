# Detection Rule: Reconnaissance - Active Scanning

Rule ID: `05e649fb-4bdf-4f4a-82ef-52b83a4c9090`

Rule Name: **Reconnaissance (T1595: Active Scanning)**

MITRE ATT&CK Tactic: [Reconnaissance](https://attack.mitre.org/tactics/TA0043/)

MITRE ATT&CK Technique: [T1595, Active Scanning](https://attack.mitre.org/techniques/T1595/)

## Description

This rule detects a potential network port scan originating from an external IP address. Active scanning is a common reconnaissance technique used by adversaries to identify open ports, discover running services, and map potential vulnerabilities on target systems before launching an attack. This activity is analogous to a burglar checking every door and window of a building to find an unlocked entry point.
An alert from this rule indicates that a single external source has attempted to connect to an abnormally high number of different ports across the network within a short time frame.

## Rule Derivation from Log Analysis

The logic for this rule was developed by modeling the digital footprint of a port scan and translating it into a query. The process involved identifying key patterns in network logs that distinguish a scan from benign traffic.

### **1. Defining the Behavior**: 

The primary goal was to identify an external actor systematically probing many network ports. The key characteristics of this behavior in raw log data are:

A high volume of connection attempts.

All attempts originate from a single source IP.

The attempts target many different destination ports.

The events occur within a condensed time frame.

The source is external to our network.


### **2. Translating Behavior to Log Fields**: 

These characteristics were then mapped to specific fields and logic available in our log data:

The "single source IP" is represented by the source.ip field.

The "many different destination ports" is identified by looking for a high number of unique values in the destination.port field.

To focus on "external" traffic, we filter out all logs where the source.ip belongs to a known internal (private RFC 1918) address range.


### **3. Constructing the Rule**: 

This analysis directly led to the rule's threshold-based design:

First, we filter for only the relevant data: inbound TCP connections from external IPs.
Next, we tell the system to group the events by source.ip, as we want to analyze the behavior of each external actor individually.

Finally, we set a threshold: an alert is triggered if any single group (a unique source IP) has a count of unique destination.port values that exceeds 50 within the rule's time window. This numeric threshold is the critical piece that separates the systematic, broad nature of a scan from normal, targeted network communication.

### **4. Detection Logic**

This is a threshold-based rule that analyzes network connection logs to identify patterns indicative of scanning behavior.

#### Query:

    event.category:network and event.type:connection and network.transport:tcp and not source.ip:(10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)

The query filters logs to isolate inbound TCP connection events.
Crucially, it excludes traffic originating from internal, private IP ranges `(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)` to prevent false positives from legitimate internal network activity.

#### Threshold:

The rule groups events by the source IP address (winlog.event_data.SourceIp.keyword).
It triggers an alert if the number of unique destination ports (winlog.event_data.DestinationPort.keyword) from a single source IP exceeds 50 within the rule's 5-minute evaluation window.

In summary, the rule alerts when a single external IP address attempts to connect to 50 or more unique ports on the network in under five minutes.

## Simulation and Validation

To validate that this rule is working correctly, a port scan can be simulated against a monitored endpoint using a tool like Nmap from an external machine.

**Atomic Red Team Test Command:**

    nmap -sT -p- <target_IP>

This command initiates a TCP connect scan (-sT) against all 65,535 ports (-p-) of the <target_IP>. This will generate a large volume of connection attempts from a single source to many distinct ports, satisfying the rule's threshold condition and triggering an alert.

