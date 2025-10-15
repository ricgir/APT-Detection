
# Detection Rule: Execution via PowerShell Download


Rule ID: **c99f9f9a-b0bd-49dc-b3af-3d837cfb64e1**

Rule Name: Execution (T1059: Command and Scripting Interpreter)

MITRE ATT&CK Tactic: [Execution](https://attack.mitre.org/tactics/TA0002/)

MITRE ATT&CK Technique: [T1059.001, Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)


## Description

This rule detects an adversary using Windows PowerShell to download a file from an external source. After gaining initial access, attackers often use this technique to retrieve their primary malware, tools, or second-stage payloads from a command-and-control (C2) server onto the compromised host.

Because PowerShell is a legitimate and powerful administration tool installed on all modern Windows systems, its activity can blend in with normal operations, making it a favored tool for "living off the land." An alert from this rule is a strong indicator that an active payload is being introduced into the environment.

## Rule Derivation from Log Analysis

This rule's logic was derived by identifying the specific command-line artifacts left behind when PowerShell is used for network downloads.


### **1. Defining the Behavior**: 

The core behavior is the execution of powershell.exe with command-line arguments that instruct it to initiate a file download from a URL.

### **2.Translating Behavior to Log Fields**: 

This activity is captured entirely within process execution logs:

- The process being run is identified in the `process.name field` (i.e., powershell.exe).
- The specific download instructions are found in the `process.command_line` field.

### **3. Constructing the Rule**: 

We identified the most common PowerShell classes, cmdlets, and aliases used for downloading files. These include the `.NET` class `System.Net.WebClient` and its methods (DownloadFile, DownloadString), as well as the native PowerShell cmdlets `Invoke-WebRequest` (aliased as iwr) and wget. The rule logic was then built to search for the execution of powershell.exe where any of these specific, high-fidelity strings are present in the command line.


## Detection Logic

This is a query-based rule that triggers on a single process creation event.

### Query:

`process.name:powershell.exe and process.command_line:(*System.Net.WebClient* or *DownloadFile* or *DownloadString* or *iwr* or *wget*)`


### Breakdown:

**process.name:powershell.exe**: The rule first looks for any event where the powershell.exe process is started.

**and**: It then requires the second condition to also be true.

**process.command_line:(...)**: The rule inspects the full command line used to launch PowerShell. It triggers if it finds any of the following keywords, which are commonly used to download files:

- System.Net.WebClient, DownloadFile, DownloadString: Methods from the .NET Framework for web requests.

- iwr: A standard alias for the Invoke-WebRequest cmdlet.

- wget: A common alias for the Invoke-WebRequest cmdlet, familiar to Linux users.

In short, the rule alerts whenever PowerShell is launched with a command that explicitly instructs it to download content from the internet.

## Simulation and Validation

This rule can be validated by running a simple PowerShell command to download a benign file from the internet.

**Atomic Red Team Test Command:**

`powershell.exe -Command "Invoke-WebRequest -Uri https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt -OutFile C:\Users\Public\license.txt"`


This command starts PowerShell and uses the Invoke-WebRequest cmdlet (iwr) to download the LICENSE.txt file from the official Atomic Red Team GitHub repository and save it to the public user's directory. This action directly matches the process.name and process.command_line logic in the rule and will generate an alert.

