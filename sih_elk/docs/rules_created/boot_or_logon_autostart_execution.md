# Detection Rule: Persistence via Registry Run Keys


Rule ID: **5a51e164-aaae-42a4-9537-00406b2f85ba**

Rule Name: Persistence (T1547: Boot or Logon Autostart Execution)

MITRE ATT&CK Tactic: [Persistence]()

MITRE ATT&CK Technique: [T1547.001, Boot or Logon Autostart Execution: Registry Run Keys]()

## Description

This rule detects when a program establishes persistence by adding an entry to the Run keys in the Windows Registry. After gaining access, an adversary uses persistence mechanisms to ensure their malicious software automatically executes every time the computer is booted or a user logs on.

This technique is one of the oldest and most common methods for maintaining a foothold. By writing to these specific registry locations, the attacker guarantees their code will survive a system reboot.


## Rule Derivation from Log Analysis

The logic for this rule was developed by targeting a well-documented and high-fidelity persistence method within Windows.

### **1. Defining the Behavior**: 

The goal was to detect the act of creating an auto-start entry. In Windows, this is most commonly done by adding a new value to one of two specific registry keys `(HKCU\...\Run or HKLM\...\Run)`. Any program path listed here is automatically executed by the operating system at startup.

### **2. Translating Behavior to Log Fields**: 

This action is captured by system monitoring tools that log registry modifications. The critical log fields are:

- event.category: This must be registry to focus on registry operations.

- registry.path: This field contains the full path to the key and value being modified.

###  **3. Constructing the Rule**: 
The query was built to be highly specific. It filters all system events for only those that are registry modifications and then checks if the path of the modification falls within the two primary `Run` keys. The wildcard (*) is used to match any new program entry being added under these keys. This approach is effective because legitimate software installations that use these keys are relatively infrequent compared to daily operations, making any modification a noteworthy event.


## Detection Logic

This is a query-based rule that triggers on a single registry modification event matching the specified criteria.

### Query:

`event.category:registry and registry.path:("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*" or "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*")`

### Explanation:
The query identifies events where a value is created or modified within the specified Windows Registry Run keys.

- The `event.category:registry` clause filters events to only include operations involving the Windows Registry
.
- The `registry.path:(...)` clause matches events where the modified path is located in one of two keys:

    - `HKEY_CURRENT_USER\...\Run\*`: This key contains programs that execute upon the current user's logon.
    
    - `HKEY_LOCAL_MACHINE\...\Run\*`: This key contains programs that execute for any user upon system startup.

The logic triggers an alert when any registry modification event occurs within these specific auto-start execution paths.


## Simulation and Validation

This rule can be validated by using the built-in Windows Registry Editor (reg.exe) to add a new startup entry.

### Atomic Red Team Test Command:

`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AtomicPersistence" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f`


This command adds a new registry value named AtomicPersistence to the current user's Run key. It instructs Windows to launch the Calculator (calc.exe) every time the user logs in. This action directly modifies one of the paths monitored by the rule and will immediately generate an alert.

