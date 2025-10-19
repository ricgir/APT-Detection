# Detection Rule: Automated Collection and Archiving

Rule ID: **3f756498-01bb-435e-92d1-5e19468abe64**

Rule Name: Collection (T1119: Automated Collection)

MITRE ATT&CK Tactic: [Collection](https://attack.mitre.org/tactics/TA0009/)

MITRE ATT&CK Technique: [T1119, Automated Collection](https://attack.mitre.org/techniques/T1119/) & [T1560.001, Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)

## Description

This rule detects the two primary stages of data collection: finding sensitive data and staging it for exfiltration. First, attackers often use scripts or built-in tools to automatically search a system for files of interest (e.g., `.doc`, `.pdf`,`.xls`). 


Next, they frequently **compress this data** into a single, often password-protected, archive file. This makes it easier for an attacker to exfiltrate a large volume of information in one go while evading simple content inspection.

## Rule Derivation from Log Analysis

The logic for this rule was developed by identifying the command-line footprint of data being staged for exfiltration.

### **1. Defining the Behavior**:

- **Automated Collection (Linux)**: The behavior is an attacker using a command-line tool like find to systematically search for files with sensitive extensions.

- **Archiving Data (Windows)**: The behavior is an attacker using a command-line utility (`7z`, `rar`, etc.) to compress document files into a password-protected archive.

### **2. Translating Behavior to Log Fields**: 

These actions are captured in process creation logs. The key fields are the process name (`process.name`) and the full command line (`process.command_line`), which contains the file types and specific switches being used.


## Detection Logic

### Windows: Archiving Collected Data

This is a query-based rule that triggers on a single process creation event.

**Query**:

`process.name:("7z.exe" or "rar.exe" or "zip.exe") and process.command_line:("*.doc*" or "*.xls*" or "*.pdf*" or "*.txt*") and process.command_line:("-p*" or "-hp*")`


**Query Explanation**:

The query identifies the use of common archiving tools to create password-protected archives of document files.

- `process.name:(...)`: This clause filters for events where a common archiving utility (7z.exe, rar.exe, zip.exe) is executed.
- `process.command_line:("*.doc*"...)`: This clause checks that the command line contains references to common document file types.
- `process.command_line:("-p*" or "-hp*")`: This clause checks for the presence of command-line switches used to set a password (-p for 7-Zip/Zip, -hp for RAR).

### Ubuntu: Automated File Search

This query looks for the use of the find command to search for files with common sensitive extensions, indicating an initial data discovery phase.

**Query**:

`process.name:"find" and process.command_line:("*.doc*" or "*.xls*" or "*.pdf*" or "*.txt*" or "*.bak*")`

**Explanation**: 

This query alerts when the `find` command is used to locate documents, spreadsheets, backups, or other potentially sensitive files, a common first step before data is staged for exfiltration.

## Simulation and Validation

### Windows

This rule can be validated by creating dummy document files and then using an archiving tool to compress them with a password.

**Test Command (PowerShell)**:

`echo "secret" > file.doc
7z.exe a -pSuperSecret collected.zip *.doc`

This test first creates a dummy document file named file.doc. It then uses the 7-Zip utility (`7z.exe`) to create a new archive named collected.zip, protecting it with a password (`-pSuperSecret`), and adds all files with a .doc extension to it. This action perfectly matches the rule's logic and will generate an alert.

### Ubuntu

This test simulates the initial data discovery phase by searching the file system for a specific file type.

Test Command:

**Step 1: Create a dummy file for the test**

`touch ~/Documents/sensitive_data.doc`

**Step 2: Run the collection command**

`find /home -name "*.doc"`

**Description**: 

This test first creates a target file and then uses the find command to search for all files with a .doc extension. This simulates an attacker's script searching the file system for valuable documents and will trigger the detection rule.


