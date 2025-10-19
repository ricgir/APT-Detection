# Detection Rule: Lateral Movement via PsExec

Rule ID: **ec5fb1d6-1f59-428e-bfb0-0086cb81fded**

Rule Name: Lateral Movement (T1021: Remote Services)

MITRE ATT&CK Tactic: [Lateral Movement](https://attack.mitre.org/tactics/TA0008/)

MITRE ATT&CK Technique: [T1021.002, Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)

## Description

This rule detects adversaries using legitimate remote access tools to move laterally from one compromised system to another within a network. By using built-in or common administrative tools, attackers can blend in with normal network traffic.

On **Windows**, a classic and powerful tool for this is **PsExec**, which uses the SMB protocol to execute commands on remote hosts. On **Linux**, the universal tool for remote access is **SSH** (Secure Shell). This rule is designed to identify suspicious usage patterns of these tools that indicate lateral movement by an attacker.

## Rule Derivation from Log Analysis

The logic for this rule is based on identifying the unique and predictable artifact created by PsExec on a target system.

### **1. Defining the Behavior**: 

The goal is to detect a remote administration tool being used to access a system.

- **Windows (PsExec)**: When **PsExec** connects to a target, it copies and runs a temporary service executable named `PSEXESVC.exe`. The creation of this process is the unique footprint.

- **Linux (SSH)**: When a user logs in via SSH, an authentication event is generated. A successful login from an internal IP address using a password is a noteworthy event, as it could indicate an attacker reusing compromised credentials.

### **2. Translating Behavior to Log Fields**:

- **Windows**: The detection uses process creation logs, focusing on the process.name.

- **Linux**: The detection uses authentication logs, focusing on event.action, ssh.method, and source.ip.

## Detection Logic

### Windows: PsExec Execution

This is a query-based rule that triggers on a single process creation event.

**Query**:

`event.category:process and process.name:PSEXESVC.exe`

**Query Explanation**:

The query identifies the execution of the PsExec service executable.

- `event.category:process`:This clause filters events to only include process creations.

- `and process.name:PSEXESVC.exe`: This clause provides the core logic, triggering an alert if the name of the process being created is exactly PSEXESVC.exe.

### Ubuntu: Internal SSH with Password

This query looks for interactive SSH sessions that use password authentication and originate from within the local network.

**Query**:

`event.category:"authentication" and event.action:"ssh_login" and ssh.method:"password" and source.ip:"10.0.0.0/8"`

**Explanation**:

This query looks for successful SSH logins that use a password and originate from an **internal IP address**. While this can be legitimate, security best practices often recommend key-based authentication for internal systems. An alert for password-based logins could indicate an attacker moving laterally with stolen credentials.

## Simulation and Validation


### Windows

This rule can be validated by using PsExec from one machine to run a command on a monitored target machine.

**Test Command (PowerShell)**:

`PsExec.exe \\<target_machine_ip> -s cmd.exe /c "whoami"`


**Description**:

This command uses PsExec to connect to the target machine and run the whoami command with SYSTEM (-s) privileges. This will cause the `PSEXESVC.exe` process to be created and run on the <target_machine_ip>, which directly matches the rule's logic and will generate an alert on the target.

### Ubuntu

This test simulates lateral movement by using SSH to log in to the local machine.

**Test Command**:

`ssh $(whoami)@localhost`

**Description**: 

This command initiates an SSH connection to `localhost` as the current user. If you authenticate with a password, this action will generate a log entry for a successful SSH login that matches the rule's logic, triggering an alert.

