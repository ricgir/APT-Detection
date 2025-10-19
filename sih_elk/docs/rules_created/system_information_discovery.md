# Detection Rule: System Information Discovery

Rule ID: **623df799-a310-464a-8294-15a0c7c7e1d8**

Rule Name: Discovery (T1082: System Information Discovery)

MITRE ATT&CK Tactic: [Discovery](https://attack.mitre.org/tactics/TA0007/)

MITRE ATT&CK Technique: [T1082, System Information Discovery](https://attack.mitre.org/techniques/T1082/)

## Description

This rule detects post-compromise reconnaissance. Attackers run a series of built-in Windows utilities to gather information about the system (its identity, network, etc.) to plan their next move.

While a single one of these commands is normal, a cluster of them in a short period strongly indicates an attacker is actively and manually exploring the compromised machine.

## Rule Derivation from Log Analysis

The logic for this rule was derived by identifying a "basket" of legitimate Windows tools that are overwhelmingly favored by attackers for initial system reconnaissance.

### **1. Defining the Behavior**: 

The goal is to detect an actor, having just landed on a machine, trying to orient themselves. They typically run a series of commands to answer basic questions: Who am I (`whoami`)? What is this machine (`systeminfo`)? What is its IP address (`ipconfig`)? What network connections exist (`net`)? What is running (`tasklist`)?

### **2. Translating Behavior to Log Fields**: 

This behavior is captured directly in process execution logs. The key field is `process.name`, which records the name of the executable that was launched.

### **3. Constructing the Rule**:

The query was built as a simple list of these key discovery-related executables. The rule's core value is not in flagging a single command, but in generating alerts that can be correlated. When multiple alerts from this rule fire from the same host in a short time window, it strongly suggests a manual discovery phase of an attack.

## Detection Logic

### Windows: Common Discovery Utilities

This is a query-based rule that triggers on a single process creation event.

**Query**:

`event.category : "process" AND process.name : ("whoami.exe" OR "systeminfo.exe" OR "ipconfig.exe" OR "net.exe" OR "tasklist.exe")`

**Query Explanation**:

The query identifies the execution of specific system discovery commands.

- `event.category : "process"`: This clause filters events to only include process creations.
- `AND process.name : (...)`: This clause triggers if the name of the process being executed is one of the following common discovery tools:
    - `whoami.exe`: Displays the current user's identity.
    - `systeminfo.exe`: Displays detailed OS and hardware information.
    - `ipconfig.exe`: Displays the host's IP configuration.
    - `net.exe`: Used for a wide range of network information gathering.
    - `tasklist.exe`: Lists currently running processes.

### Ubuntu: Common Discovery Utilities

**Query**:

`event.action:"executed" and process.name:("whoami" or "hostname" or "uname" or "ifconfig" or "ip" or "netstat")`

This query alerts on the execution of common Linux discovery tools used to find the current user (`whoami`), system information (`hostname`, `uname`), and network configuration (`ifconfig`, `ip`, `netstat`).

## Simulation and Validation

### Windows

This rule can be validated by executing the targeted commands from a Command Prompt or PowerShell session.

**Test Command (PowerShell)**:

```
whoami
hostname
systeminfo
ipconfig /all
netstat -an
tasklist
```

This sequence of commands mimics an attacker performing initial reconnaissance on a host. Each command execution creates a process event that matches one of the names in the rule's query (`whoami.exe, systeminfo.exe`, etc.), which will generate a corresponding alert.

### Ubuntu

This test simulates an attacker efficiently chaining multiple discovery commands together in a single line.

**Test Command**:

`whoami && hostname && uname -a && ip a`

This chain of commands is a common attacker shortcut that quickly provides the current username, system hostname, kernel version, and network interface configuration, triggering multiple alerts in rapid succession.

