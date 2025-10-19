# Detection Rule: OS Credential Dumping via LSASS

Rule ID: **49fcd163-9359-4472-8f27-47315023d94a**

Rule Name: Credential Access (T1003: OS Credential Dumping)

MITRE ATT&CK Tactic: [Credential Access](https://attack.mitre.org/tactics/TA0006/)

MITRE ATT&CK Technique: [T1003, OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)

## Description

This rule detects adversaries attempting to extract account login and credential material directly from the operating system. This is a critical step for attackers to escalate privileges and move laterally across a network.

On **Windows**, a primary target for this is the **Local Security Authority Subsystem Service (LSASS)** process memory, which stores valuable credentials like password hashes for active users. On **Linux**, the equivalent is the `/etc/shadow` file, which contains the hashed passwords for all local user accounts.

## Rule Derivation from Log Analysis

The logic for this rule is based on identifying highly suspicious activities directed at these critical credential stores.

### **1. Defining the Behavior**: 

The goal is to detect unauthorized access to credential storage locations.

- **Windows (Masquerading)**: The provided rule detects a common precursor or accompanying technique where malware **masquerades as the LSASS process** to hide its activity. Any creation of `lsass.exe` by an unexpected parent process is a strong indicator of malicious intent.

- **Linux (Direct Access)**: The logic focuses on detecting direct, unauthorized access to the `/etc/shadow` file. Legitimate access to this file is rare and performed only by a few known system utilities.

### **2. Translating Behavior to Log Fields**: 

- **Windows**: The detection uses process creation logs, focusing on `process.name` and the parent process `source.process.executable`.

- **Linux**: The detection uses file access logs, focusing on file.path, event.action, and the `process.name` that is accessing the file.

### **3. Constructing the Rule**: 

The query is constructed to specifically look for the creation of `lsass.exe` while excluding a shortlist of common system processes that might be false positives. Any other parent process is flagged as suspicious, providing a high-fidelity alert for this masquerading technique.

## Detection Logic

### Windows: LSASS Process Masquerading

This is a query-based rule that triggers on a single process creation event.

**Query**:

`event.category:process and event.action:"Process Create" and process.name:lsass.exe and source.process.executable:* and not source.process.executable:("C:\\Windows\\System32\\svchost.exe" or "C:\\Windows\\System32\\services.exe")`

**Query Explanation**:

The query identifies events where a process named lsass.exe is created by an unauthorized parent process.

- `event.category:process and event.action:"Process Create"`: This clause filters events to only include new process creations.

- `process.name:lsass.exe`: This specifically looks for the creation of a process with the name lsass.exe.

- `not source.process.executable:(...)`: This clause excludes legitimate system processes (svchost.exe, services.exe) from being flagged as the parent, reducing potential noise.

The rule triggers an alert if lsass.exe is created by any process not on the exclusion list, which is highly anomalous behavior.

### Ubuntu: Unauthorized /etc/shadow Access

This query alerts when a process other than a standard system utility attempts to read the `/etc/shadow` file.

**Query**:

`file.path:"/etc/shadow" and event.action:"opened" and not process.name:("passwd" or "chage" or "useradd" or "login")`

Direct access to `/etc/shadow` is highly suspicious. This query looks for any process reading this file that isn't a known, legitimate utility for managing passwords and users.

## Simulation and Validation

### Windows

This rule can be validated by simulating a malware masquerading technique where a common utility is renamed to `lsass.exe` and executed.

**Test Command (PowerShell)**:

`copy C:\Windows\System32\whoami.exe C:\Users\Public\lsass.exe
C:\Users\Public\lsass.exe`


This test first copies a harmless utility, whoami.exe, to a new location and renames it to `lsass.exe`. When the renamed file is executed, a new process named lsass.exe is created. The parent process will be the shell that executed the command (e.g., cmd.exe or powershell.exe), which is not on the rule's exclusion list. This action directly matches the rule's logic and will generate an alert.

### Ubuntu

This test simulates a direct attempt to read the credential file.

**Test Command**:

`sudo cat /etc/shadow`

This command uses cat to attempt to read the `/etc/shadow` file. Since cat is not a standard password management utility on the exclusion list, this action directly matches the rule's logic and will generate an alert.
