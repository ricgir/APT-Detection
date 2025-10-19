# Detection Rule: Defense Evasion via Encoded PowerShell Command

Rule ID: **9ddec47a-5d4c-465c-be29-ea27ce6340b8**

Rule Name: Defense Evasion (T1027: Obfuscated Files or Information)

MITRE ATT&CK Tactic: [Defense Evasion](https://attack.mitre.org/tactics/TA0005/)

MITRE ATT&CK Technique: [T1027, Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)

## Description

This rule detects attackers using obfuscation techniques to hide their commands, tools, or data from security software. By encoding commands or hiding files, adversaries can evade signature-based scanners and manual inspection. An alert from this rule is a strong indicator of intentional evasion. 

On Windows, a classic technique is using **Base64-encoded PowerShell commands**. This abuses a legitimate feature to hide malicious keywords from detection. On Linux, evasion can involve hiding data in less common locations like alternate data streams or simply storing tools and payloads in hidden **"dotfiles"**.

## Rule Derivation from Log Analysis

The logic for this rule focuses on the specific artifacts of the obfuscation method, rather than the unreadable obfuscated content itself.

### **1. Defining the Behavior**: 

The goal is to detect the execution of a command or tool that is specifically designed to handle obfuscated data.

- **Windows**: The key behavior is the execution of `powershell.exe` with a specific command-line switch (`-EncodedCommand`) that instructs it to decode and run a Base64 string.

- **Linux**: The behavior involves using a powerful utility like `dd` with a specific syntax (`of=*:*`) that indicates writing to a non-standard file stream.

### **2. Translating Behavior to Log Fields**: 

This information is found within process creation logs:

- The executed process is in `process.name` (e.g., `powershell.exe`, `dd`).

- The specific switches or arguments are in `process.args` or `process.command_line`.

### **3. Constructing the Rule**: 

We identified the unique command-line arguments used for these techniques. The rule triggers when it sees a process launched with these high-fidelity indicators. While these features have legitimate uses, they are far more common in malicious and unauthorized activity.


## Detection Logic

### Windows

This is a query-based rule that triggers on a single process creation event.

**Query**:

`process.name : "powershell.exe" AND (process.args:"-e" OR process.args:"-en" OR process.args:"-enc" OR process.args:"-encodedcommand")`

**Query Explanation**:

The query identifies events where the PowerShell interpreter is launched with arguments that specify an encoded command.

- The `process.name : "powershell.exe"` clause filters for events where the PowerShell process is started.

- The AND (...) clause provides the core logic, checking if the process arguments (`process.args`) contain any of the switches used to pass a Base64-encoded command string: -e, -en, -enc, or the full -encodedcommand.

The rule triggers an alert if powershell.exe is executed with any of these specific command-line switches.

### Ubuntu: Hiding Data with `dd`

**Query**:

`process.name:"dd" and process.command_line: "*of=*:*"`

This query looks for the use of the `dd` utility with a command line that contains `of=*:*`. This syntax can be used to write to an alternate data stream on certain file systems, a technique for hiding malicious data from normal view.


## Simulation and Validation

### Windows

This rule can be validated by encoding a simple command into Base64 and executing it using the `-EncodedCommand` switch.

**Test Command (PowerShell)**:

`powershell.exe -EncodedCommand dwBoAG8AYQBtAGkA`


This command executes PowerShell and instructs it to run an encoded command. The Base64 string dwBoAG8AYQBtAGkA decodes to the simple command whoami. The PowerShell process decodes the string and executes whoami in memory. This action, which uses powershell.exe and the `-EncodedCommand` switch (which can be shortened to `-e, -en, or -enc`), directly matches the rule's logic and will generate an alert.

### Ubuntu

This test simulates a simple but effective evasion technique: hiding a file by naming it with a leading dot.

**Test Command**:
    
`echo "hidden malware" > ~/.im_not_a_virus`

This command creates a new file named `.im_not_a_virus` in the user's home directory. In Linux, files starting with a dot (`.`) are hidden from standard directory listings (like `ls`). This simulates an attacker trying to hide their artifacts on the system and is a common form of defense evasion.
