# APT Threat Lifecycle & Detection Coverage

This document outlines the stages of an Advanced Persistent Threat (APT) lifecycle, mapped to the MITRE ATT&CK framework. Each stage includes a description of the adversary's objective, a concise detection strategy, a placeholder for your rule, and a link to the relevant Atomic Red Team test.

## 1. Reconnaissance (T1595: Active Scanning)
**Description:**  
Adversaries probe victim networks and systems to identify potential vulnerabilities, open ports, and running services. This helps them map the target's external footprint before launching an attack.

**Detection Strategy:**  
Identifies brute-force patterns by detecting a high volume of failed logins from a single IP, a common byproduct of active scanning.

[Detection Rule (Windows & Ubuntu)](rules_created/active_scanning.md)


**Atomic Red Team Reference (Windows only):**  
[T1595.003 - Scanning IP Blocks](https://www.atomicredteam.io/atomic-red-team/atomics/T1595.003)

---

## 2. Initial Access (T1566: Phishing)
**Description:**  
Attackers send fraudulent emails containing malicious attachments or links to gain a foothold in the network.

**Detection Strategy:**  
Detects anomalous parent-child process relationships, such as an email client spawning a script or executable.

[Detection Rule (Windows & Ubuntu)](rules_created/phishing.md)

**Atomic Red Team Reference (Windows only):**  
[T1566.001 - Spearphishing Attachment](https://www.atomicredteam.io/atomic-red-team/atomics/T1566.001)

---

## 3. Execution (T1059: Command and Scripting Interpreter)
**Description:**  
Adversaries use command-line interfaces (like PowerShell) to execute malicious commands and scripts.

**Detection Strategy:**  
Alerts on PowerShell execution using command-line flags (`-enc`, `-encodedcommand`) designed to run obfuscated or encoded commands.

[Detection Rule (Windows & Ubuntu)](rules_created/command_and_scripting_interpreter.md)

**Atomic Red Team Reference (Windows only):**  
[T1059 - Command and Scripting Interpreter](https://www.atomicredteam.io/atomic-red-team/atomics/T1059)

---

## 4. Persistence (T1547: Boot or Logon Autostart Execution)
**Description:**  
Attackers configure malware to run automatically by modifying registry keys, startup folders, or logon scripts.

**Detection Strategy:**  
Monitors for modifications to common registry "Run" keys.

[Detection Rule (Windows & Ubuntu)](rules_created/boot_or_logon_autostart_execution.md)

**Atomic Red Team Reference (Windows only):**  
[T1547 - Boot or Logon Autostart Execution](https://www.atomicredteam.io/atomic-red-team/atomics/T1547)

---

## 5. Privilege Escalation (T1548: Abuse Elevation Control Mechanism)
**Description:**  
Adversaries exploit system mechanisms that manage user permissions, such as UAC on Windows, to gain higher-level privileges.

**Detection Strategy:**  
Detects a known UAC bypass by identifying when `fodhelper.exe` anomalously spawns a command shell.

[Detection Rule (Windows & Ubuntu)](rules_created/abuse_elevation_control_mechanism.md)

**Atomic Red Team Reference (Windows only):**  
[T1548.001 - Setuid and Setgid](https://www.atomicredteam.io/atomic-red-team/atomics/T1548.001)

---

## 6. Defense Evasion (T1027: Obfuscated Files or Information)
**Description:**  
Attackers conceal their malicious code to avoid detection, often using encryption, encoding, or packing.

**Detection Strategy:**  
Flags the use of `certutil.exe` with the `-decode` flag.

[Detection Rule (Windows & Ubuntu)](rules_created/obfuscated_files_or_information.md)

**Atomic Red Team Reference (Windows only):**  
[T1027 - Obfuscated Files or Information](https://www.atomicredteam.io/atomic-red-team/atomics/T1027)

---

## 7. Credential Access (T1003: OS Credential Dumping)
**Description:**  
Extracting account login material from the OS, often by dumping memory from the LSASS process.

**Detection Strategy:**  
Detects unauthorized processes attempting to access the memory of `lsass.exe`.

[Detection Rule (Windows & Ubuntu)](rules_created/os_credential_dumping.md)

**Atomic Red Team Reference (Windows only):**  
[T1003 - OS Credential Dumping](https://www.atomicredteam.io/atomic-red-team/atomics/T1003)

---

## 8. Discovery (T1082: System Information Discovery)
**Description:**  
Attackers collect detailed information about the compromised system.

**Detection Strategy:**  
Looks for a rapid burst of system discovery commands from a single process.

[Detection Rule (Windows & Ubuntu)](rules_created/system_information_discovery.md)

**Atomic Red Team Reference (Windows only):**  
[T1082 - System Information Discovery](https://www.atomicredteam.io/atomic-red-team/atomics/T1082)

---

## 9. Lateral Movement (T1021: Remote Services)
**Description:**  
Adversaries use legitimate remote access tools like RDP to move between systems.

**Detection Strategy:**  
Identifies non-standard RDP connections by flagging sessions not initiated by `svchost.exe`.

[Detection Rule (Windows & Ubuntu)](rules_created/remote_services.md)

**Atomic Red Team Reference (Windows only):**  
[T1021.001 - Remote Desktop Protocol](https://www.atomicredteam.io/atomic-red-team/atomics/T1021.001)

---

## 10. Collection (T1119: Automated Collection)
**Description:**  
Attackers use scripts to automatically search for and gather files containing sensitive data.

**Detection Strategy:**  
Alerts on the rapid creation of numerous sensitive file types by a shell process.

[Detection Rule (Windows & Ubuntu)](rules_created/automated_collection.md)

**Atomic Red Team Reference (Windows only):**  
[T1119 - Automated Collection](https://www.atomicredteam.io/atomic-red-team/atomics/T1119)

---

## 11. Command and Control (C2) (T1071: Application Layer Protocol)
**Description:**  
Adversaries use common protocols like HTTP to blend C2 traffic with legitimate activity.

**Detection Strategy:**  
Flags network connections from non-browser processes to common code-hosting sites.

[Detection Rule (Windows & Ubuntu)](rules_created/application_layer_protocol.md)

**Atomic Red Team Reference (Windows only):**  
[T1071 - Application Layer Protocol](https://www.atomicredteam.io/atomic-red-team/atomics/T1071)

---

## 12. Exfiltration (T1048: Exfiltration Over Alternative Protocol)
**Description:**  
Data is stolen by transmitting it over an alternative protocol, such as DNS.

**Detection Strategy:**  
Detects potential DNS tunneling by identifying abnormally long DNS queries.

[Detection Rule (Windows & Ubuntu)](rules_created/exfiltration_over_alternative_protocol.md)

**Atomic Red Team Reference (Windows only):**  
[T1048 - Exfiltration Over Alternative Protocol](https://www.atomicredteam.io/atomic-red-team/atomics/T1048)