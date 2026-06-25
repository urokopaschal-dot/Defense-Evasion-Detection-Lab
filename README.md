# Defense-Evasion-Detection-La# Defense Evasion Detection Lab

## Project Overview

This project demonstrates how attackers use defense evasion techniques to avoid detection and how a SOC Analyst can identify these activities using Splunk and Sysmon.

The lab focuses on three common defense evasion techniques:

* Windows Event Log Clearing
* Obfuscated PowerShell
* Renamed LOLBins (Living Off The Land Binaries)

The objective is to generate telemetry, investigate suspicious activity, and map findings to the MITRE ATT&CK framework.

---

# Tools Used

* Windows 10 VM
* Splunk
* Sysmon
* PowerShell
* Command Prompt

---

# Technique 1: Windows Event Log Clearing

## Description

Attackers often clear Windows Event Logs to remove evidence of their actions and make investigations more difficult.

## Attack Simulation

The following command was executed:

```cmd
wevtutil cl security
```

## Detection

Windows generates Event ID 1102 when the Security log is cleared.

Splunk Search:

```spl
index=wineventlog EventCode=1102
```

## Investigation Findings

The investigation confirmed that the Windows Security Event Log was cleared. This behavior is highly suspicious because attackers frequently remove logs after malicious activity to hinder forensic analysis.

## MITRE ATT&CK

| Technique                | ID        |
| ------------------------ | --------- |
| Clear Windows Event Logs | T1070.001 |

---

# Technique 2: Obfuscated PowerShell

## Description

Attackers commonly obfuscate PowerShell commands using Base64 encoding to evade detection and hide malicious activity.

## Attack Simulation

The following encoded PowerShell command was executed:

```powershell
powershell.exe -nop -w hidden -enc SQBFAFgA
```

## Detection

Splunk Search:

```spl
index=sysmon EventCode=1 CommandLine="*-enc*" 
| stats count by _time Image ParentImage CommandLine
| sort -_time
```

## Investigation Findings

The command line contained the -enc parameter, indicating that the PowerShell command was encoded. Encoded PowerShell commands are commonly associated with malware execution and post-exploitation activity.

## MITRE ATT&CK

| Technique                       | ID    |
| ------------------------------- | ----- |
| Obfuscated Files or Information | T1027 |

---

# Technique 3: Renamed LOLBin

## Description

Living Off The Land Binaries (LOLBins) are legitimate Windows utilities frequently abused by attackers. To avoid detection, attackers may rename these binaries to appear harmless.

## Attack Simulation

A copy of certutil.exe was renamed and executed.

Example:

```cmd
copy C:\Windows\System32\certutil.exe C:\Temp\updater.exe
```

Execution:

```cmd
C:\Temp\updater.exe -?
```

## Detection

Splunk Search:

```spl
index=sysmon EventCode=1 Image="*updater.exe"
```

Alternative Search:

```spl
index=sysmon EventCode=1 OriginalFileName=certutil.exe
```

## Investigation Findings

The investigation identified execution of a renamed Windows binary. Although the executable appeared as updater.exe, analysis revealed it originated from certutil.exe, a commonly abused LOLBin.

## MITRE ATT&CK

| Technique    | ID    |
| ------------ | ----- |
| Masquerading | T1036 |

---

# Summary of Findings

The investigation identified multiple defense evasion techniques used by attackers to avoid detection:

| Technique                     | MITRE ID  |
| ----------------------------- | --------- |
| Log Clearing                  | T1070.001 |
| Obfuscated PowerShell         | T1027     |
| Masquerading (Renamed LOLBin) | T1036     |

The generated telemetry was successfully collected by Sysmon and investigated using Splunk. The findings demonstrate how common defense evasion techniques can be detected and analyzed within a SOC environment.

---

# Conclusion

This project demonstrates practical detection and investigation of defense evasion techniques using Sysmon and Splunk. The lab highlights the importance of monitoring event logs, PowerShell activity, and suspicious process execution to identify attacker attempts to avoid detection.
