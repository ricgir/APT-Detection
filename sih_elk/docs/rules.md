<!-- [Active Scanning](rules_created/active_scanning.md)

[Phishing](rules_created/phishing.md)

[Command and Scripting Interpreter](rules_created/command_and_scripting_interpreter.md)

[Boot or Logon Autostart Execution](rules_created/boot_or_logon_autostart_execution.md)

[Abuse Elevation Control Mechanism](rules_created/abuse_elevation_control_mechanism.md)

[Obfuscated Files or Information](rules_created/obfuscated_files_or_information.md)

[OS Credential Dumping](rules_created/os_credential_dumping.md)

[System Information Discovery](rules_created/system_information_discovery.md)

[Remote Services](rules_created/remote_services.md)

[Automated Collection](rules_created/automated_collection.md)

[Application Layer Protocol](rules_created/application_layer_protocol.md)

[Exfiltration Over Alternative Protocol](rules_created/exfiltration_over_alternative_protocol.md) -->

# Detection Rule Repository

This page serves as the central repository for all detection rules developed for this project. Each rule is mapped to a specific **MITRE ATT&CK®** tactic and technique, and the link will take you to a detailed page with the KQL query and implementation notes.

---

## All Rules

| Rule Name                                                                              | MITRE ATT&CK Tactic   | Technique ID                                                               | Description                                                 |
| :------------------------------------------------------------------------------------- | :-------------------- | :------------------------------------------------------------------------- | :---------------------------------------------------------- |
| [Active Scanning](rules_created/active_scanning.md)                                    | Reconnaissance        | [T1595](https://attack.mitre.org/techniques/T1595/)                         | Detects brute-force patterns indicative of network scanning.      |
| [Phishing](rules_created/phishing.md)                                                  | Initial Access        | [T1566](https://attack.mitre.org/techniques/T1566/)                         | Identifies email clients spawning suspicious child processes.     |
| [Command and Scripting Interpreter](rules_created/command_and_scripting_interpreter.md) | Execution             | [T1059](https://attack.mitre.org/techniques/T1059/)                         | Flags PowerShell execution with encoded command flags.            |
| [Boot or Logon Autostart Execution](rules_created/boot_or_logon_autostart_execution.md) | Persistence           | [T1547](https://attack.mitre.org/techniques/T1547/)                         | Monitors for modifications to common registry "Run" keys.       |
| [Abuse Elevation Control Mechanism](rules_created/abuse_elevation_control_mechanism.md) | Privilege Escalation  | [T1548](https://attack.mitre.org/techniques/T1548/)                         | Detects a known UAC bypass using `fodhelper.exe`.                 |
| [Obfuscated Files or Information](rules_created/obfuscated_files_or_information.md)     | Defense Evasion       | [T1027](https://attack.mitre.org/techniques/T1027/)                         | Alerts on the use of `certutil.exe` to decode files.              |
| [OS Credential Dumping](rules_created/os_credential_dumping.md)                         | Credential Access     | [T1003](https://attack.mitre.org/techniques/T1003/)                         | Identifies unauthorized processes accessing `lsass.exe` memory.   |
| [System Information Discovery](rules_created/system_information_discovery.md)           | Discovery             | [T1082](https://attack.mitre.org/techniques/T1082/)                         | Looks for a rapid burst of system discovery commands.             |
| [Remote Services](rules_created/remote_services.md)                                     | Lateral Movement      | [T1021](https://attack.mitre.org/techniques/T1021/)                         | Flags non-standard RDP connections.                             |
| [Automated Collection](rules_created/automated_collection.md)                           | Collection            | [T1119](https://attack.mitre.org/techniques/T1119/)                         | Detects rapid creation of sensitive file types by a shell.      |
| [Application Layer Protocol](rules_created/application_layer_protocol.md)               | Command and Control   | [T1071](https://attack.mitre.org/techniques/T1071/)                         | Flags non-browser processes connecting to code-hosting sites.   |
| [Exfiltration Over Alternative Protocol](rules_created/exfiltration_over_alternative_protocol.md) | Exfiltration          | [T1048](https://attack.mitre.org/techniques/T1048/)                         | Detects abnormally long DNS queries indicative of tunneling.    |

---

> **Note**: Click on any rule name to view its detailed documentation, including the full KQL query, data source requirements, and validation steps.