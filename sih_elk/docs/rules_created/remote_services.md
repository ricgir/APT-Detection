# Detection Rule: Lateral Movement via PsExec

Rule ID: **ec5fb1d6-1f59-428e-bfb0-0086cb81fded**

Rule Name: Lateral Movement (T1021: Remote Services)

MITRE ATT&CK Tactic: [Lateral Movement](https://attack.mitre.org/tactics/TA0008/)

MITRE ATT&CK Technique: [T1021.002, Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)

## Description

Adversaries use legitimate remote access tools to move from one compromised system to another. This rule detects the use of **PsExec**, a common systems administration tool, for lateral movement.

Because **PsExec** is a legitimate tool, its use can blend in with normal administrative activity. However, it is also a favorite of attackers for executing commands on remote systems. The rule specifically looks for the creation of the `PSEXESVC.exe` service on a host, which is the unique footprint left by PsExec during its operation.

## Rule Derivation from Log Analysis

The logic for this rule is based on identifying the unique and predictable artifact created by PsExec on a target system.

### **1. Defining the Behavior**: 

When PsExec is used to run a command on a remote machine, it first copies a service executable named `PSEXESVC.exe` to the `SYSTEM32` directory of the target and then starts this service. The service then executes the desired command.

### **2. Translating Behavior to Log Fields**:

This behavior is captured as a process creation event in the logs of the target machine. The key field is process.name, which will be `PSEXESVC.exe`.

### **3. Constructing the Rule**: 

The query was built to simply detect the creation of this specific process. Since `PSEXESVC.exe` should not be running for any other reason, its presence is a high-fidelity indicator that PsExec was used to access the machine.

## Detection Logic

This is a query-based rule that triggers on a single process creation event.

### Query:

`event.category:process and process.name:PSEXESVC.exe`

### Query Explanation:

The query identifies the execution of the PsExec service executable.

- `event.category:process`:This clause filters events to only include process creations.

- `and process.name:PSEXESVC.exe`: This clause provides the core logic, triggering an alert if the name of the process being created is exactly PSEXESVC.exe.

## Simulation and Validation

This rule can be validated by using PsExec from one machine to run a command on a monitored target machine.

### Atomic Red Team Test Command:

`PsExec.exe \\<target_machine_ip> -s cmd.exe /c "whoami"`


## Description:

This command uses PsExec to connect to the target machine and run the whoami command with SYSTEM (-s) privileges. This will cause the `PSEXESVC.exe` process to be created and run on the <target_machine_ip>, which directly matches the rule's logic and will generate an alert on the target.

