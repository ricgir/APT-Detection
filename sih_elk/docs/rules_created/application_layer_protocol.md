
# Detection Rule: C2 via Application Layer Protocol

Rule ID: **a2b74aea-b267-4ddd-9a51-bac87083d306**

Rule Name: Command and Control (T1071: Application Layer Protocol)

MITRE ATT&CK Tactic: [Command and Control](https://attack.mitre.org/tactics/TA0011/)

MITRE ATT&CK Technique: [T1071, Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)

## Description

Adversaries use common protocols like **HTTP** or **HTTPS** for their command and control (C2) communications to blend in with legitimate network traffic.

This rule detects this behavior by identifying network connections to standard web ports (80/443) that originate from non-browser processes. While it's normal for browsers like Chrome or Firefox to connect to these ports, it is highly suspicious when other programs (like `cmd.exe`, `powershell.exe`, or an unknown executable) do so, as this can indicate a malware beacon.

## Rule Derivation from Log Analysis

The logic for this rule was developed by baselining normal web traffic and then hunting for outliers.

### **1. Defining the Behavior**: 

The goal was to find C2 traffic hiding as legitimate web browsing. The key differentiator is the **source process**. Legitimate HTTP/S traffic originates from a web browser or a few core system processes. Malicious C2 traffic often originates from malware, droppers, or script interpreters.

### **2. Translating Behavior to Log Fields**: 

This behavior is observed in network connection logs.

- The network protocol is identified by the destination.port (80 for HTTP, 443 for HTTPS).

- The source process is identified by `process.name`.

### **3. Constructing the Rule**: 

The query was built using an exclusion model. It looks for all traffic on web ports and then explicitly excludes connections from known, legitimate browsers and system processes. Any remaining traffic is flagged as suspicious, providing a powerful way to spot hidden C2 channels.

## Detection Logic

This is a query-based rule that triggers on a single network connection event.

### Query:

`event.category:network and destination.port:(80 or 443) and not process.name:("chrome.exe" or "firefox.exe" or "msedge.exe" or "iexplore.exe" or "svchost.exe")`

### Query Explanation:

The query identifies network traffic from non-standard applications to web ports.

- `event.category:network`: This clause filters events to only include network connections.

- `destination.port:(80 or 443)`: This filters for traffic directed to the standard ports for HTTP (80) and HTTPS (443).

- `not process.name:(...)`: This is the core logic, which excludes traffic originating from common web browsers and the Windows Service Host (svchost.exe).

## Simulation and Validation

This rule can be validated by initiating a web request from a non-browser application, such as PowerShell.

### Atomic Red Team Test Command:

`Invoke-WebRequest -Uri https://www.google.com`

This command uses PowerShell's Invoke-WebRequest cmdlet to download the homepage of Google. This creates a network connection from the `powershell.exe` process to a destination on port 443 (HTTPS). Since powershell.exe is not in the rule's exclusion list, this action directly matches the rule's logic and will generate an alert.

