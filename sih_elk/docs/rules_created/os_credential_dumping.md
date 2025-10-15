# Detection Rule: OS Credential Dumping via LSASS

Rule ID: **49fcd163-9359-4472-8f27-47315023d94a**

Rule Name: Credential Access (T1003: OS Credential Dumping)

MITRE ATT&CK Tactic: [Credential Access](https://attack.mitre.org/tactics/TA0006/)

MITRE ATT&CK Technique: [T1003, OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)

## Description

This technique involves extracting account login and credential material from the operating system's memory. Adversaries specifically target the **Local Security Authority Subsystem Service (LSASS)** process on Windows because it stores valuable credentials (like password hashes and Kerberos tickets) for active user sessions.
By dumping the memory of the lsass.exe process, an attacker can extract these credentials and use them for lateral movement across the network. This rule is designed to detect suspicious activity targeting this critical process.

## Rule Derivation from Log Analysis

The logic for this rule is based on identifying anomalous process creation events that masquerade as the legitimate LSASS process.

### **1. Defining the Behavior**: 

The legitimate `lsass.exe` process is started by `wininit.exe` during the system boot sequence. It should never be created by another process during a normal user session. Therefore, any creation of a process named lsass.exe by an unexpected parent is a strong indicator of malicious activity, such as malware attempting to hide by impersonating a critical system process.

### **2. Translating Behavior to Log Fields**: 

This behavior is captured in process creation logs, focusing on the parent-child relationship:

- The event type is a Process Create event.

- The child process name (`process.name`) is lsass.exe.

- The parent process name (`source.process.executable`) is the key field to inspect for anomalies.

### **3. Constructing the Rule**: 

The query is constructed to specifically look for the creation of `lsass.exe` while excluding a shortlist of common system processes that might be false positives. Any other parent process is flagged as suspicious, providing a high-fidelity alert for this masquerading technique.

## Detection Logic

This is a query-based rule that triggers on a single process creation event.

### Query:

`event.category:process and event.action:"Process Create" and process.name:lsass.exe and source.process.executable:* and not source.process.executable:("C:\\Windows\\System32\\svchost.exe" or "C:\\Windows\\System32\\services.exe")`

### Query Explanation:

The query identifies events where a process named lsass.exe is created by an unauthorized parent process.

- `event.category:process and event.action:"Process Create"`: This clause filters events to only include new process creations.

- `process.name:lsass.exe`: This specifically looks for the creation of a process with the name lsass.exe.

- `not source.process.executable:(...)`: This clause excludes legitimate system processes (svchost.exe, services.exe) from being flagged as the parent, reducing potential noise.

The rule triggers an alert if lsass.exe is created by any process not on the exclusion list, which is highly anomalous behavior.

## Simulation and Validation

This rule can be validated by simulating a malware masquerading technique where a common utility is renamed to `lsass.exe` and executed.

### Atomic Red Team Test Command:

`copy C:\Windows\System32\whoami.exe C:\Users\Public\lsass.exe
C:\Users\Public\lsass.exe`


This test first copies a harmless utility, whoami.exe, to a new location and renames it to `lsass.exe`. When the renamed file is executed, a new process named lsass.exe is created. The parent process will be the shell that executed the command (e.g., cmd.exe or powershell.exe), which is not on the rule's exclusion list. This action directly matches the rule's logic and will generate an alert.

