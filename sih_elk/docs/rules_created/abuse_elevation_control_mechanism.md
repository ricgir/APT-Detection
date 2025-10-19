# Detection Rule: Privilege Escalation via Fodhelper UAC Bypass

Rule ID: **6727ae6d-21ee-40aa-b0a1-bbcb1c58f8cf**

Rule Name: Privilege Escalation (T1548: Abuse Elevation Control Mechanism)

MITRE ATT&CK Tactic: [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)

MITRE ATT&CK Technique: [T1548.002, Abuse Elevation Control Mechanism: Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002/)

## Description

This rule detects adversaries abusing built-in elevation control mechanisms to execute code with higher privileges. This is a critical step for an attacker to move from a standard user context to an administrator or root context, granting them full control over the system.

On Windows, a common technique is to bypass User Account Control (UAC) by exploiting legitimate applications that are allowed to auto-elevate, such as `fodhelper.exe`. On Linux, a precursor to privilege escalation is often discovering what permissions the current user has, which is frequently done using the `sudo -l` command.

## Rule Derivation from Log Analysis

The logic for this rule is derived by identifying adversary actions that are highly indicative of an attempt to gain higher privileges.

### **1. Defining the Behavior**: 

The goal is to detect either the active bypass of a security control or the reconnaissance that precedes it.

- **Windows (Bypass)**: The focus is on an untrusted process launching a trusted, auto-elevating executable like `fodhelper.exe`. This anomalous parent-child relationship is a strong indicator of a hijack.

- **Linux (Discovery)**: The focus is on an adversary checking what commands they can run with elevated privileges. The `sudo -l` command is a specific artifact of this discovery behavior.


### **2. Translating Behavior to Log Fields**: 

- **Windows**: The child process (`process.name`) and its parent (`process.parent.name`) are analyzed.

- **Linux**: The process (`process.name`) and its specific arguments (`process.args`) are inspected.


### **3. Constructing the Rule**: 

The Windows query identifies the execution of `fodhelper.exe` and then excludes known legitimate parent processes, flagging any remaining instance as suspicious.

The Ubuntu query looks for the specific combination of the `sudo` process being run with the `-l` argument, a high-fidelity indicator of privilege discovery.

## Detection Logic

### Windows: Fodhelper UAC Bypass

This is a query-based rule that triggers on a single process creation event matching a specific parent-child relationship.

**Query**:

`process.name : "fodhelper.exe" AND NOT (process.parent.name : "explorer.exe" OR process.parent.name : "svchost.exe")`

**Query Explanation**:

The query logic identifies instances where fodhelper.exe is executed by a process other than its expected parent processes.
- The `process.name : "fodhelper.exe"` clause selects all events where the fodhelper.exe process is created.
- The `AND NOT (...)` clause then filters out these events if the parent process (`process.parent.name`) is either `explorer.exe` or `svchost.exe`, which are considered legitimate initiators.

The rule triggers an alert for any fodhelper.exe process creation event that does not match the exclusion criteria, indicating a high probability of a UAC bypass attempt.


### Ubuntu: Sudo Permissions Discovery

This query looks for a user attempting to list their sudo permissions, which is often a precursor to privilege escalation.

**Query**:

`process.name:"sudo" and process.args:"-l"`

**Explanation**: 

This query alerts when the `sudo` command is run with the `-l` (list) flag. Before attempting to escalate privileges, an attacker will almost always use this command to discover what commands they are permitted to run as root.

## Simulation and Validation

### Windows

This rule can be validated by simulating the registry hijack and execution flow used in this UAC bypass technique.

**Test Command (PowerShell)**:

`reg add HKCU\Software\Classes\ms-settings\shell\open\command /v "" /d "C:\Windows\System32\cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\shell\open\command /v "DelegateExecute" /d "" /f
fodhelper.exe`

This sequence of commands first modifies the registry key associated with the ms-settings URI handler, pointing it to the Command Prompt (`cmd.exe`). When fodhelper.exe is executed in the final step, it attempts to open the settings handler, but because of the registry modification, it launches cmd.exe with elevated privileges instead. This action, where `cmd.exe` (or another shell) becomes the parent of fodhelper.exe, matches the rule's logic and will generate an alert.

### Ubuntu

This test simulates the discovery step an attacker takes after gaining initial access.

**Test Command**:

`sudo -l`

This command uses the `-l` (list) option of sudo to show which commands the current user is permitted to run with elevated privileges. Running this command directly matches the rule's logic and will generate an alert.

