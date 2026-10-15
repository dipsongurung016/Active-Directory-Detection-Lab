# Case Study 02 — Atomic Red Team Telemetry in Splunk

**Date:** 14 October 2026  
**Test endpoint:** `TARGET-PC`, Windows 10 (`silicon.local`)  
**Tools:** Atomic Red Team, PowerShell, Sysmon, Splunk Enterprise  
**Collection:** `index=endpoint`, Sysmon Operational events  
**Scope:** Authorised local virtual machine testing only

## Objective

Run selected Atomic Red Team exercises, identify their process activity in Splunk, and assess what was detected **separately from whether the test achieved its intended objective**.

I investigated two ATT&CK sub-techniques:

- [T1595.003 — Active Scanning: Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003/)
- [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

## 1. T1595.003 — Wordlist Scanning

### Test execution

On `TARGET-PC`, I attempted the following Atomic Red Team test:

```powershell
Invoke-AtomicTest T1595.003
```

The test output identified **`T1595.003-1 Web Server Wordlist Scan`** and returned:

```text
Error: Target is not reachable
Exit code: 1
Done executing test: T1595.003-1 Web Server Wordlist Scan
```

![Atomic T1595.003 PowerShell test output](../screenshots/12-atomic-t1595-wordlist-test.png)

*Figure 12 — The test was initiated, but the target was unreachable. A successful scan is not established.*

### What Splunk detected

The Splunk search `index=endpoint T1595` produced **one matching event** in the displayed one-hour window. The visible XML event contains:

| Field | Observation |
|---|---|
| Host | `target-PC` |
| Source | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Sysmon Event ID | **1 — Process Create** |
| Process | `powershell.exe` |
| Command line | References the `T1595.003` Atomic directory, `WordlistScan.ps1` and `Invoke-WordlistScan` |
| Sysmon `RuleName` | `technique_id=T1083`, File and Directory Discovery |

![Sysmon Process Create event for Atomic wordlist scan](../screenshots/13-atomic-t1595-sysmon-detection.png)

*Figure 13 — Splunk records the PowerShell process associated with the T1595.003 attempt.*

The process-creation event proves that the related PowerShell command was observed. It **does not** prove that the wordlist scan successfully reached or enumerated a web server.

**Technique-label distinction:** `T1595.003` is the Atomic exercise I attempted. `T1083` appears in the Sysmon `RuleName` attached to the event; it should not be presented as proof of a separate executed Atomic test.

### Investigation search

The original broad search used in the screenshot was:

```spl
index=endpoint T1595
```

A more specific follow-up query to try over the same test window is:

```spl
index=endpoint host="target-PC" EventCode=1 "T1595.003"
| table _time host EventCode Message
| sort -_time
```

The narrower query is proposed for repeatable investigation; it was **not separately validated** in the supplied evidence.

## 2. T1059.001 — PowerShell

### Test execution

I also invoked the Atomic PowerShell technique:

```powershell
Invoke-AtomicTest T1059.001
```

At least two attempted tests were visible:

| Attempt | Outcome shown in PowerShell |
|---|---|
| `T1059.001-1 Mimikatz` | Process start failed: **Access is denied** |
| `T1059.001-2 Run BloodHound from local disk` | `Invoke-BloodHound` not recognised; required SharpHound PowerShell module/script could not be loaded |

![PowerShell errors during T1059.001 tests](../screenshots/14-atomic-t1059-powershell-test.png)

*Figure 14 — Atomic T1059.001 attempts and the reported errors.*

These test outputs are **not proof** that credential extraction or BloodHound enumeration completed.

### What Splunk detected

The broad query:

```spl
index=endpoint T1059
```

returned **1,447 matches** during the selected one-hour period.

![Broad T1059 search results in Splunk](../screenshots/15-atomic-t1059-splunk-events.png)

*Figure 15 — A broad search returned 1,447 related matches; that does not mean 1,447 attacks took place.*

I also ran a more focused search:

```spl
index=endpoint technique_id="T1059.001" AtomicRedTeam
```

It returned **three matching events** in the displayed 15-minute window. The visible events include **Sysmon Event ID 7 (Image Loaded)** activity involving `amsi.dll` and process paths/commands associated with the Atomic Red Team materials.

![Focused T1059.001 Sysmon results](../screenshots/16-atomic-t1059-001-detection.png)

*Figure 16 — Three focused Sysmon search matches for T1059.001-related activity. A password argument visible in the original command line was redacted before publication.*

These are evidence of **telemetry visibility**, not proof that the PowerShell Atomic tests completed successfully or that a dedicated, automated detection alert fired.

## 3. Detection and analysis summary

| Exercise | Endpoint outcome | What was observed in Splunk | Conclusion |
|---|---|---|---|
| `T1595.003` Wordlist Scanning | Target unreachable; exit code 1 | Sysmon Event ID 1 containing the attempted PowerShell command | Execution attempt visible; scan outcome not achieved |
| `T1059.001` PowerShell | Access denied / missing dependencies | Broad T1059 matches and three focused T1059.001-related Sysmon Event ID 7 records | Associated activity visible; intended test objectives not established |

### SOC lessons

1. **Process telemetry and attack success are different questions.** Splunk can show that PowerShell launched while the test itself fails.
2. **Search-result counts require context.** Neither 1,447 broad matches nor three focused matches equal the number of attacks performed.
3. **ATT&CK tags are metadata, not verdicts.** A Sysmon rule label should be assessed against the actual executable, command line, timestamp and test output.
4. **Test prerequisites matter.** An unreachable HTTP target or missing modules can prevent completion even if the monitoring pipeline is functioning.

## 4. Limitations and possible next steps

The provided evidence demonstrates that Windows/Sysmon telemetry associated with Atomic Red Team reached Splunk. It does **not** establish successful web scanning, successful Mimikatz execution, a completed BloodHound collection, an automated Splunk alert, or fully validated detection logic.

For a follow-up exercise, I would choose a low-impact Atomic test, review its prerequisites and cleanup steps, confirm the test completed, and correlate its execution timestamp with the appropriate Sysmon/Windows events. Any test-created artefacts should be checked and removed as needed.

**Project reference:** This lab followed [MyDFIR's Active Directory home-lab tutorial](https://www.youtube.com/@MyDFIR). The screenshots and analysis document my own authorised lab observations.
