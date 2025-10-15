# Detection Rule: Defense Evasion via Encoded PowerShell Command

Rule ID: **9ddec47a-5d4c-465c-be29-ea27ce6340b8**

Rule Name: Defense Evasion (T1027: Obfuscated Files or Information)

MITRE ATT&CK Tactic: [Defense Evasion](https://attack.mitre.org/tactics/TA0005/)

MITRE ATT&CK Technique: [T1027, Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)

## Description

This rule detects attackers using Base64-encoded PowerShell commands to evade security software. This "living off the land" technique hides malicious keywords (like `Invoke-Mimikatz`) from signature-based scanners by abusing a legitimate PowerShell feature. An alert from this rule indicates that an adversary is intentionally obfuscating their commands on the system..


## Rule Derivation from Log Analysis

The logic for this rule was derived by focusing on how an obfuscated command is executed, rather than on the content of the command itself, which is unreadable.

### **1. Defining the Behavior**: 
The key behavior is the execution of powershell.exe with a specific command-line argument that instructs it to decode and then run a Base64 string. The presence of these specific arguments is the primary indicator of this evasion technique.

### **2. Translating Behavior to Log Fields**: 
The required information is found entirely within process creation logs:

- The executed process is captured in the process.name field (`powershell.exe`).

- The specific switches used to handle encoded data are found in the `process.args` or 
`process.command_line` field.

### **3. Constructing the Rule**: 
We identified all the valid switches that PowerShell uses to accept an encoded command. The full switch is `-EncodedCommand`, but this can be abbreviated to -enc, -en, or -e. The rule was built to look for the execution of powershell.exe where **any of these four switches** are present in the command line. This is a high-fidelity detection because, while legitimate administrative scripts can use this feature, it is far more common in malicious and unauthorized activity.


## Detection Logic

This is a query-based rule that triggers on a single process creation event.

### Query:

`process.name : "powershell.exe" AND (process.args:"-e" OR process.args:"-en" OR process.args:"-enc" OR process.args:"-encodedcommand")`

### Query Explanation:

The query identifies events where the PowerShell interpreter is launched with arguments that specify an encoded command.

- The `process.name : "powershell.exe"` clause filters for events where the PowerShell process is started.

- The AND (...) clause provides the core logic, checking if the process arguments (`process.args`) contain any of the switches used to pass a Base64-encoded command string: -e, -en, -enc, or the full -encodedcommand.

The rule triggers an alert if powershell.exe is executed with any of these specific command-line switches.


## Simulation and Validation

This rule can be validated by encoding a simple command into Base64 and executing it using the `-EncodedCommand` switch.

### Atomic Red Team Test Command:

`powershell.exe -EncodedCommand dwBoAG8AYQBtAGkA`


This command executes PowerShell and instructs it to run an encoded command. The Base64 string dwBoAG8AYQBtAGkA decodes to the simple command whoami. The PowerShell process decodes the string and executes whoami in memory. This action, which uses powershell.exe and the `-EncodedCommand` switch (which can be shortened to `-e, -en, or -enc`), directly matches the rule's logic and will generate an alert.

