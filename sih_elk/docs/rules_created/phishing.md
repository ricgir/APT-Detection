# Detection Rule: Initial Access via Phishing

Rule ID: 51bac7dd-1389-4819-8812-50dc46744934

Rule Name: **Initial Access (T1566: Phishing)**

MITRE ATT&CK Tactic: [Initial Access](https://attack.mitre.org/tactics/TA0001/)

MITRE ATT&CK Technique: [T1566, Phishing](https://attack.mitre.org/techniques/T1566/)

## Description

This rule detects a common initial access pattern where a Microsoft Office application (Word, Excel, etc.) launches a command-line or scripting interpreter. This behavior is highly indicative of a successful phishing attack where a user has opened a malicious document containing embedded macros or exploits.

Adversaries use this technique to gain an initial foothold on a system. The script executed by the Office application typically serves as a "dropper" or "downloader" to fetch the next stage of the malware payload from an external server.

## Rule Derivation from Log Analysis

The logic for this rule is based on identifying anomalous parent-child process relationships. Benign usage of Microsoft Office almost never involves the direct creation of a script interpreter.

### **1. Defining the Behavior**: 

The core of the attack is an Office application executing malicious code. In system process logs, this action is recorded as the Office process (e.g., winword.exe) starting a new, separate process, such as powershell.exe. The Office application is the parent, and the script interpreter is the child.

### **2. Translating Behavior to Log Fields**: 

This relationship is directly observable in log data:

The parent process is identified by the process.parent.name field.

The child process is identified by the process.name field.

### **3. Constructing the Rule**: 

The query was built to find this specific, high-fidelity malicious pattern. We created a list of common Office parent processes and a list of powerful script interpreters that are frequently abused by attackers. The rule then triggers an alert only when a process from the first list spawns a process from the second list. This specific parent-child combination is a very strong indicator of compromise.

## Detection Logic

This is a query-based rule that triggers on a single event matching the specified process creation pattern.

### Query:

`process.parent.name:("winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe") and process.name:("powershell.exe" or "cmd.exe" or "wscript.exe" or "mshta.exe")`


### Breakdown:

- process.parent.name:(...): This part of the query looks for an event where the parent (creating) process is a Microsoft Office application like Word, Excel, PowerPoint, or Outlook.

- and: This logical operator requires both conditions to be true.

- process.name:(...): This part looks for the child (created) process being a common script interpreter such as PowerShell, Command Prompt, Windows Script Host, or MSHTA (which executes HTML application files).

In short, the rule alerts when an Office application is used to launch a command shell or script engine.

## Simulation and Validation

This rule can be validated by creating a macro-enabled Microsoft Word document that executes a simple command.

### Atomic Red Team Test Procedure:

- Open Microsoft Word and create a new blank document.

- Press ALT + F11 to open the Visual Basic for Applications (VBA) editor.

- In the project window, double-click ThisDocument and paste the following code:
VBA
```
    Sub AutoOpen() 
    ` This macro will run automatically when the document is opened and macros are enabled.
    ` It launches PowerShell to execute the 'whoami command.
    CreateObject("WScript.Shell").Run powershell.exe -c whoami, 0, True
End Sub
```


- Save the document as a "Word Macro-Enabled Document" (.docm).

- Close and reopen the document on a monitored endpoint. When prompted, click "Enable Content".

This action will cause winword.exe to spawn powershell.exe, which precisely matches the rule's logic and should trigger an alert.


