# Detection Rule: Privilege Escalation via Fodhelper UAC Bypass

Rule ID: **6727ae6d-21ee-40aa-b0a1-bbcb1c58f8cf**

Rule Name: Privilege Escalation (T1548: Abuse Elevation Control Mechanism)

MITRE ATT&CK Tactic: [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)

MITRE ATT&CK Technique: [T1548.002, Abuse Elevation Control Mechanism: Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002/)

## Description

This rule detects a specific User Account Control (UAC) bypass technique that abuses the legitimate Windows executable `fodhelper.exe`. Adversaries exploit this mechanism to execute code with elevated (administrator) privileges on a compromised system without triggering the standard UAC prompt that would alert the user.

`fodhelper.exe` is a trusted Microsoft binary that is allowed to auto-elevate its privileges. Attackers can hijack its execution by modifying specific registry keys. When `fodhelper.exe` is launched, it inadvertently executes the attacker's malicious command instead of its intended function, inheriting the elevated privileges.

## Rule Derivation from Log Analysis

The logic for this rule is derived from analyzing the process execution chain during a UAC bypass, focusing on anomalous parent-child relationships.

### **1. Defining the Behavior**: 

The attack involves an untrusted process (like `cmd.exe` or a malicious script) launching `fodhelper.exe` to trigger the hijack. In normal operations, `fodhelper.exe` is typically launched by core Windows processes like the user's shell (`explorer.exe`) or the Service Host (`svchost.exe`). Therefore, the key indicator of malicious activity is `fodhelper.exe` being started by an unexpected parent process.


### **2. Translating Behavior to Log Fields**: 
This parent-child relationship is captured in process creation logs:

- The child process is identified in the process.name field (as `fodhelper.exe`).
- The parent process that launched it is identified in the process.parent.name field.


### **3. Constructing the Rule**: 
The query was built to be highly specific and reduce false positives. It first identifies all instances of `fodhelper.exe` being executed. Then, it explicitly excludes the known, legitimate parent processes. Any remaining event, where `fodhelper.exe` is launched by any other process, is treated as suspicious and triggers an alert.

## Detection Logic

This is a query-based rule that triggers on a single process creation event matching a specific parent-child relationship.

### Query:

`process.name : "fodhelper.exe" AND NOT (process.parent.name : "explorer.exe" OR process.parent.name : "svchost.exe")`

### Query Explanation:

The query logic identifies instances where fodhelper.exe is executed by a process other than its expected parent processes.
- The `process.name : "fodhelper.exe"` clause selects all events where the fodhelper.exe process is created.
- The `AND NOT (...)` clause then filters out these events if the parent process (`process.parent.name`) is either `explorer.exe` or `svchost.exe`, which are considered legitimate initiators.

The rule triggers an alert for any fodhelper.exe process creation event that does not match the exclusion criteria, indicating a high probability of a UAC bypass attempt.


## Simulation and Validation

This rule can be validated by simulating the registry hijack and execution flow used in this UAC bypass technique.

### Atomic Red Team Test Command:

`reg add HKCU\Software\Classes\ms-settings\shell\open\command /v "" /d "C:\Windows\System32\cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\shell\open\command /v "DelegateExecute" /d "" /f
fodhelper.exe`

This sequence of commands first modifies the registry key associated with the ms-settings URI handler, pointing it to the Command Prompt (`cmd.exe`). When fodhelper.exe is executed in the final step, it attempts to open the settings handler, but because of the registry modification, it launches cmd.exe with elevated privileges instead. This action, where `cmd.exe` (or another shell) becomes the parent of fodhelper.exe, matches the rule's logic and will generate an alert.

