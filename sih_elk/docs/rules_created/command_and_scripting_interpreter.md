
# Detection Rule: Execution via PowerShell Download


Rule ID: **c99f9f9a-b0bd-49dc-b3af-3d837cfb64e1**

Rule Name: Execution (T1059: Command and Scripting Interpreter)

MITRE ATT&CK Tactic: [Execution](https://attack.mitre.org/tactics/TA0002/)

MITRE ATT&CK Technique: [T1059.001, Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)


## Description

This rule detects adversaries using native command and scripting interpreters, such as **PowerShell** on **Windows** or **Bash** on **Linux**, to execute malicious code. Because these tools are installed by default and used for legitimate administration, attackers favor them for "living off the land" to download payloads, run obfuscated commands, and evade defenses.

On Windows, this often involves using PowerShell to download malware from a command-and-control (C2) server. On Linux, a common technique is to use Bash to decode and execute obfuscated scripts to hide the true payload. An alert from this rule is a strong indicator of malicious execution on a host.

## Rule Derivation from Log Analysis

This rule's logic was derived by identifying specific, high-fidelity artifacts left in the command line when an interpreter is used for malicious activity.


### **1. Defining the Behavior**: 

The core behavior is the execution of an interpreter (`powershell.exe`, `bash`) with command-line arguments that instruct it to perform a suspicious action, such as downloading a file or decoding an obfuscated string.

### **2.Translating Behavior to Log Fields**: 

This activity is captured entirely within process execution logs:

- The process being run is identified in the `process.name field` (i.e., powershell.exe).
- The specific download instructions are found in the `process.command_line` field.

### **3. Constructing the Rule**: 

We identified common cmdlets, classes, and keywords used for these malicious activities. The rule logic was then built to search for the execution of a target interpreter where these specific strings are present in the command line.

## Detection Logic

### Windows: Detecting PowerShell Downloads

This is a query-based rule that triggers on a single process creation event.

**Query**:

    process.name:powershell.exe and process.command_line:(*System.Net.WebClient* or *DownloadFile* or *DownloadString* or *iwr* or *wget*)

**Breakdown**:

**process.name:powershell.exe**: The rule first looks for any event where the powershell.exe process is started.

**and**: It then requires the second condition to also be true.

**process.command_line:(...)**: The rule inspects the full command line used to launch PowerShell. It triggers if it finds any of the following keywords, which are commonly used to download files:

- System.Net.WebClient, DownloadFile, DownloadString: Methods from the .NET Framework for web requests.

- iwr: A standard alias for the Invoke-WebRequest cmdlet.

- wget: A common alias for the Invoke-WebRequest cmdlet, familiar to Linux users.

In short, the rule alerts whenever PowerShell is launched with a command that explicitly instructs it to download content from the internet.

### Ubuntu: Detecting Obfuscated Bash Commands

**Query**:

    process.name:"bash" and process.command_line:"*base64*" and process.command_line:"*decode*"

**Breakdown**: 

This query searches for instances where the bash shell is used with command-line arguments to decode a Base64 encoded string. Attackers use this encoding (obfuscation) technique to hide their malicious scripts from simple keyword detection.

## Simulation and Validation

This rule can be validated by running a simple PowerShell command to download a benign file from the internet.

### Windows

**Test Command (PowerShell)**:

`powershell.exe -Command "Invoke-WebRequest -Uri https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt -OutFile C:\Users\Public\license.txt"`


This command starts PowerShell and uses the Invoke-WebRequest cmdlet (iwr) to download the LICENSE.txt file from the official Atomic Red Team GitHub repository and save it to the public user's directory. This action directly matches the process.name and process.command_line logic in the rule and will generate an alert.

### Ubuntu

This test executes a Base64-encoded version of the whoami command, mimicking how attackers hide commands.

**Test Command**:

    echo "d2hvYW1p" | base64 --decode | bash


In this command, `d2hvYW1p` is the Base64 encoding for "whoami". The `echo` command sends this string to the `base64 --decode` command, which translates it back to "whoami". The result is then piped directly into `bash` for execution. This simulates the technique of running deobfuscated code and is designed to be caught by rules monitoring for this behavior.

