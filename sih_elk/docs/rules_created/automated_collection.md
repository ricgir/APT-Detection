# Detection Rule: Automated Collection and Archiving

Rule ID: **3f756498-01bb-435e-92d1-5e19468abe64**

Rule Name: Collection (T1119: Automated Collection)

MITRE ATT&CK Tactic: [Collection](https://attack.mitre.org/tactics/TA0009/)

MITRE ATT&CK Technique: [T1119, Automated Collection](https://attack.mitre.org/techniques/T1119/) & [T1560.001, Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)

## Description

Attackers use scripts to automatically gather sensitive files (.doc, .pdf, etc.). This rule detects a common follow-up action: compressing these files into a password-protected archive using tools like 7z or rar. This action stages the data, making it easier for an attacker to exfiltrate a large volume of information in a single, encrypted file.

## Rule Derivation from Log Analysis

The logic for this rule was developed by identifying the command-line footprint of data being staged for exfiltration.

### **1. Defining the Behavior**:

An adversary, after identifying files of interest, will often use a command-line utility to compress them into a password-protected archive. This behavior involves three key components: an archiving tool, target files (often documents), and a password.

### **2. Translating Behavior to Log Fields**: 

This entire action is captured in a single process creation event.

- The archiving utility is found in `process.name`.
- The files being targeted and the password switch are both found in the process.command_line.

### **3. Constructing the Rule**: 

The query was built to require all three behavioral components to be present. It looks for a known archiving tool, common document file extensions in the command line, and the specific command-line switches used for password protection. The combination of these three elements is a very strong indicator of malicious data staging.


## Detection Logic

This is a query-based rule that triggers on a single process creation event.

### Query:

`process.name:("7z.exe" or "rar.exe" or "zip.exe") and process.command_line:("*.doc*" or "*.xls*" or "*.pdf*" or "*.txt*") and process.command_line:("-p*" or "-hp*")`


### Query Explanation:

The query identifies the use of common archiving tools to create password-protected archives of document files.

- `process.name:(...)`: This clause filters for events where a common archiving utility (7z.exe, rar.exe, zip.exe) is executed.
- `process.command_line:("*.doc*"...)`: This clause checks that the command line contains references to common document file types.
- `process.command_line:("-p*" or "-hp*")`: This clause checks for the presence of command-line switches used to set a password (-p for 7-Zip/Zip, -hp for RAR).

## Simulation and Validation

This rule can be validated by creating dummy document files and then using an archiving tool to compress them with a password.

### Atomic Red Team Test Command:

`echo "secret" > file.doc
7z.exe a -pSuperSecret collected.zip *.doc`

This test first creates a dummy document file named file.doc. It then uses the 7-Zip utility (7z.exe) to create a new archive named collected.zip, protecting it with a password (-pSuperSecret), and adds all files with a .doc extension to it. This action perfectly matches the rule's logic and will generate an alert.

