
# Detection Rule: C2 via Application Layer Protocol

Rule ID: **a2b74aea-b267-4ddd-9a51-bac87083d306**

Rule Name: Command and Control (T1071: Application Layer Protocol)

MITRE ATT&CK Tactic: [Command and Control](https://attack.mitre.org/tactics/TA0011/)

MITRE ATT&CK Technique: [T1071, Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)

## Description

This rule detects adversaries using common protocols like HTTP or HTTPS for their command and control (C2) communications to blend in with legitimate network traffic. This is a common method for malware to "beacon" out for instructions.

To spot this, we look for anomalies. On **Windows**, this rule identifies network connections to standard web ports (80/443) that originate from **non-browser processes**. On **Linux**, it identifies outbound network connections from processes running out of **suspicious locations**, such as the `/tmp` directory.

## Rule Derivation from Log Analysis

The logic for this rule was developed by baselining normal traffic and then hunting for high-fidelity outliers that indicate malicious C2 activity.

### **1. Defining the Behavior**: 

The goal is to find C2 traffic hiding in plain sight. The key differentiators are the source of the traffic.

- **Windows**: Legitimate web traffic originates from a browser. Malicious C2 traffic often originates from malware, droppers, or script interpreters (like `powershell.exe`).

- **Linux**: Legitimate applications are installed in standard locations like `/usr/bin`. Malware is often dropped and executed from world-writable directories like `/tmp`.

### **2. Translating Behavior to Log Fields**: 

This behavior is observed in network connection and process logs.

- **Windows**: We inspect the `destination.port` and the source `process.name`.

- **Linux**: We inspect the source `process.executable` path and the `network.direction`.


## Detection Logic

### Windows: Non-Browser Web Traffic

This is a query-based rule that triggers on a single network connection event.

**Query**:

`event.category:network and destination.port:(80 or 443) and not process.name:("chrome.exe" or "firefox.exe" or "msedge.exe" or "iexplore.exe" or "svchost.exe")`

**Query Explanation**:

The query identifies network traffic from non-standard applications to web ports.

- `event.category:network`: This clause filters events to only include network connections.

- `destination.port:(80 or 443)`: This filters for traffic directed to the standard ports for HTTP (80) and HTTPS (443).

- `not process.name:(...)`: This is the core logic, which excludes traffic originating from common web browsers and the Windows Service Host (svchost.exe).

### Ubuntu: Outbound Connection from /tmp

This query looks for network connections from a process running out of a suspicious, temporary location.

**Query**:

`process.executable:"/tmp/*" and network.direction:"outbound"`

**Explanation**: 

Legitimate applications do not typically run from the `/tmp` directory. This query alerts on any process running from `/tmp` that is making an outbound network connection, which is a strong indicator of a C2 beacon.

## Simulation and Validation

### Windows

This rule can be validated by initiating a web request from a non-browser application, such as PowerShell.

**Test Command (PowerShell)**:

`Invoke-WebRequest -Uri https://www.google.com`

This command uses PowerShell's Invoke-WebRequest cmdlet to download the homepage of Google. This creates a network connection from the `powershell.exe` process to a destination on port 443 (HTTPS). Since powershell.exe is not in the rule's exclusion list, this action directly matches the rule's logic and will generate an alert.

### Ubuntu

This test simulates an attacker downloading and executing their tool from `/tmp` to establish a C2 channel.

**Test Command**:

`cp /usr/bin/curl /tmp/legit_process && /tmp/legit_process http://example.com -o /dev/null`

**Description**: 

This command copies the curl utility to `/tmp` and then runs it from that location to make an outbound web request. This action of a process in `/tmp` making an outbound connection perfectly matches the rule's logic and will generate an alert.

