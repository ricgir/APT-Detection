# Detection Rule: Persistence via Registry Run Keys


Rule ID: **5a51e164-aaae-42a4-9537-00406b2f85ba**

Rule Name: Persistence (T1547: Boot or Logon Autostart Execution)

MITRE ATT&CK Tactic: [Persistence]()

MITRE ATT&CK Technique: [T1547.001, Boot or Logon Autostart Execution: Registry Run Keys]()

## Description

This rule detects when a program establishes persistence by creating an entry in a common autostart location. After gaining access, an adversary uses persistence mechanisms to ensure their malicious software automatically executes every time the computer is booted or a user logs on. This is one of the most common methods for maintaining a foothold.

On Windows, this is typically done by adding an entry to the Registry Run Keys. On Linux, this is achieved by placing a script or service file in an autostart directory such as `/etc/cron.d/` or `/etc/systemd/system/`. By writing to these specific locations, the attacker guarantees their code will survive a system reboot.


## Rule Derivation from Log Analysis

The logic for this rule was developed by targeting a well-documented and high-fidelity persistence method within Windows.

### **1. Defining the Behavior**: 

The goal was to detect the act of creating or modifying an auto-start entry. This could be a new value added to a Windows Registry Run key or a new file placed in a Linux autostart directory..

### **2. Translating Behavior to Log Fields**: 

This action is captured by system monitoring tools that log registry or file system modifications. The critical log fields are:

- **Windows**: `event.category:registry` and `registry.path`.

- **Linux**: `file.path` and `event.action` (looking for "created" or "updated").

###  **3. Constructing the Rule**: 

The query was built to be highly specific. It filters all system events for only those that are registry or file modifications and then checks if the path of the modification falls within a list of known autostart locations. The wildcard (*) is used to match any new program entry. This approach is effective because changes to these locations are relatively infrequent during normal operations, making any modification a noteworthy event.


## Detection Logic

This is a query-based rule that triggers on a single registry modification event matching the specified criteria.

### Windows

**Query**:

`event.category:registry and registry.path:("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*" or "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*")`

**Explanation**:

The query identifies events where a value is created or modified within the specified Windows Registry Run keys.

- The `event.category:registry` clause filters events to only include operations involving the Windows Registry
.
- The `registry.path:(...)` clause matches events where the modified path is located in one of two keys:

    - `HKEY_CURRENT_USER\...\Run\*`: This key contains programs that execute upon the current user's logon.
    
    - `HKEY_LOCAL_MACHINE\...\Run\*`: This key contains programs that execute for any user upon system startup.

The logic triggers an alert when any registry modification event occurs within these specific auto-start execution paths.


### Ubuntu: Autostart Directories & Services

**Query**:

`file.path: ("/etc/systemd/system/*" or "/home/*/.config/autostart/*" or "/etc/cron.d/*" or "/etc/rc.local") and event.action: ("created" or "updated")`

**Explanation**:

This query alerts on the creation or modification of files in common Linux directories that are used for autostarting applications and services, such as systemd unit files, user autostart directories, and cron job directories.

## Simulation and Validation

### Windows

This rule can be validated by using the built-in Windows Registry Editor (reg.exe) to add a new startup entry.

**Test Command (PowerShell)**:

`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AtomicPersistence" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f`


This command adds a new registry value named AtomicPersistence to the current user's Run key. It instructs Windows to launch the Calculator (calc.exe) every time the user logs in. This action directly modifies one of the paths monitored by the rule and will immediately generate an alert.

### Ubuntu

This test creates a new file in a cron.d directory, a common location for cron-based persistence.

**Test Command**:

`sudo touch /etc/cron.d/malicious_persistence`


Creating a file in the `/etc/cron.d` directory is a common persistence technique. This simple `touch` command creates a new file in a monitored location and should trigger a file integrity monitoring alert based on the rule's logic. The file can be removed afterward with `sudo rm /etc/cron.d/malicious_persistence`.