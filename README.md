# Brute Force Detection Lab — Kali, Windows 10, and Splunk

**Author:** Eli Bessey

## Overview

This project simulates a brute force authentication attack against a Windows 10 host and detects it using Splunk SIEM. The lab demonstrates the full attack-to-detection lifecycle: username enumeration, password guessing, a successful compromise, and the log analysis used to identify each stage — plus a real-world discrepancy between an attack tool's self-reported output and the authoritative evidence in the Windows Security event log.

**Skills demonstrated:** SIEM log analysis, Windows Security event auditing, brute force attack simulation, SPL (Search Processing Language), log-based verification of tool output, and incident analysis/reporting.

---

## Lab Architecture

| Component | Role | Details |
|---|---|---|
| Kali Linux | Attacker | IP: `192.168.10.250`, hostname `kali`, tools: Crowbar, Hydra |
| Windows 10 | Target | Hostname: `Bob-Win.Elidsi.local`, local account `bob`, IP `192.168.10.40` |
| Splunk | SIEM / log analysis | Index: `endpoint`, source: `WinEventLog:Security` |

**Networking:** Both VMs sit on the same private virtual network (`192.168.10.0/24`), allowing Kali to reach Windows directly over RDP (port 3389) for the attack.

<img width="900" height="665" alt="NetworkDiagram" src="https://github.com/user-attachments/assets/d06ed573-fc2b-4a3e-9d4b-521916d16681" />

---

## Lab Configuration

Rather than a step-by-step install log, this section documents the configuration that makes detection possible.

### Windows Audit Policy

```
Logon                 Success and Failure
Logoff                Success
Account Lockout       Success
Special Logon         Success
```

`Logon: Success and Failure` is what generates Event ID 4624 (successful logon) and Event ID 4625 (failed logon) — the two events this project relies on.

<img width="511" height="256" alt="lab-configuration" src="https://github.com/user-attachments/assets/5afe84bd-5cd0-4702-93d1-0b051464da31" />


### Splunk Data Inputs

Windows event logs are collected via a local forwarder configuration feeding the `endpoint` index:

```
[WinEventLog://Security]
index = endpoint
disabled = false

[WinEventLog://Application]
index = endpoint
disabled = false

[WinEventLog://System]
index = endpoint
disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = endpoint
disabled = false
renderXml = true
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

<img width="570" height="644" alt="Screenshot 2026-11-07 021525" src="https://github.com/user-attachments/assets/365a063f-798a-460d-8e86-4244a6b4c8aa" />

### Versions

Kali Linux: [fill in] · Windows 10: [build] · Splunk: 10.6.0.5 · Crowbar: v0.4.2 · Hydra: v9.7

---

## Attack

### Attempt 1: Crowbar

**Command:**
```bash
crowbar -b rdp -u bob -C passwords.txt -s 192.168.10.40/32
```

**Target:** `192.168.10.40:3389` (Windows 10 host, local account `bob`)

<img width="1892" height="545" alt="Screenshot 2026-11-07 110211" src="https://github.com/user-attachments/assets/6b7725cd-7608-4aaf-9e86-878c49ca157b" />


**Result:** Crowbar reported `RDP-SUCCESS` for every password in the wordlist — 22 out of 22 attempts, including obviously incorrect ones. This is inconsistent with how a brute force against a single valid password should behave, and is addressed in the Findings section below.

### Attempt 2: Hydra (cross-validation)

To verify Crowbar's results, the same wordlist was run against Hydra:

```bash
hydra -l bob -P passwords.txt rdp://192.168.10.40 -t 4 -W 3
```

<img width="1900" height="909" alt="Screenshot 2026-11-07 115735" src="https://github.com/user-attachments/assets/b3511f5f-e9de-40ec-a70d-29295719089a" />


**Result:** Hydra's RDP module (labeled "experimental" by its own developers) failed to establish a connection for any attempt (`[ERROR] freerdp: The connection failed to establish`), returning zero valid passwords found. This is a known limitation of Hydra's FreeRDP backend in some lab configurations.

**Conclusion:** Neither attack tool's console output could be trusted as ground truth. This is why the project pivoted to the Windows Security event log — collected independently of either tool — as the authoritative record of what actually happened.

---

## Detection and Analysis

All queries below run against `index=endpoint`, `source="WinEventLog:Security"`.

### 1. Identifying the attack source

```spl
index=endpoint source="WinEventLog:Security" EventCode=4625
| rex "Source Network Address:\s+(?<src_ip>\S+)"
| stats count by src_ip
| sort - count
```

**Result:** All 91 failed logon events in the 24-hour window traced back to a single source: `192.168.10.250` (Kali).

<img width="1909" height="825" alt="Screenshot 2026-11-07 105345" src="https://github.com/user-attachments/assets/05e24f74-3543-447d-b8fa-889799657832" />

### 2. Enumeration vs. password guessing

Breaking failed logons down by target username and NTLM sub-status code revealed two distinct phases of the attack:

```spl
index=endpoint source="WinEventLog:Security" EventCode=4625
| rex "Source Network Address:\s+(?<src_ip>\S+)"
| rex "Sub Status:\s+(?<sub_status>\S+)"
| rex "Account For Which Logon Failed:\s+Security ID:\s+\S+\s+Account Name:\s+(?<target_user>\S+)"
| search src_ip="192.168.10.250"
| stats count by target_user, sub_status
```

| Target Username | Sub Status | Count | Meaning |
|---|---|---|---|
| bob | 0xC0000064 | 22 | "User name does not exist" |
| bob | 0xC000006A | 4 | "Correct user name, bad password" |
| elidsibob | 0xC0000064 | several | "User name does not exist" (true enumeration — account never existed) |

**Analysis:** `bob` is a real account, yet most attempts against it returned "user name does not exist" rather than "bad password." The `Account Domain` field explains why: it was populated (`ELIDSI`) on the 4 attempts that returned `0xC000006A`, but blank (`-`) on the others. When the domain wasn't resolved, Windows couldn't match `bob` to the real account and returned the enumeration error instead of the password error — a byproduct of how the attack tool qualified (or failed to qualify) the username on each attempt.

<img width="1906" height="827" alt="Screenshot 2026-11-07 114850" src="https://github.com/user-attachments/assets/e98088a8-994a-4c30-9a76-a3f2e1796cea" />


<img width="1915" height="910" alt="Screenshot 2026-11-07 115001" src="https://github.com/user-attachments/assets/8397f1fb-fb23-4417-bfff-0bd418cd6387" />


### 3. Volume and timing

```spl
index=endpoint source="WinEventLog:Security" EventCode=4625
| rex "Source Network Address:\s+(?<src_ip>\S+)"
| search src_ip="192.168.10.250"
| timechart span=1m count
```

The chart shows four distinct attack bursts across the 24-hour window, each corresponding to a separate Crowbar/Hydra run — evidence of repeated, deliberate attack attempts rather than background noise.

<img width="1897" height="902" alt="Screenshot 2026-11-07 105244" src="https://github.com/user-attachments/assets/56b68464-49df-4369-b6b3-86faf4c771de" />


### 4. Confirmed compromise

```spl
index=endpoint source="WinEventLog:Security" EventCode=4624
| rex "Source Network Address:\s+(?<src_ip>\S+)"
| rex "Logon Type:\s+(?<logon_type>\d+)"
| search src_ip="192.168.10.250" logon_type="3"
```

At **08:58:20.009 AM**, 23 seconds after the last captured password-guess attempt, a successful Event ID 4624 confirmed the account was compromised:

| Field | Value |
|---|---|
| Logon Type | 3 (network) |
| Account Name | Bob |
| Account Domain | ELIDSI |
| Workstation Name | kali |
| Source Network Address | 192.168.10.250 |
| Authentication Package | NTLM V2 |

This is the **single, authoritative successful logon** recorded by Windows — in contrast to Crowbar's console, which claimed 22 successes.

**[Insert screenshot: raw 4624 event]**
*(You have this)*

### Summary of the attack chain

1. **Enumeration/mismatched attempts** — failed logons against `bob` and `elidsibob` returning "user name does not exist" (Sub Status `0xC0000064`)
2. **Password guessing** — failed logons against the real account `bob` returning "bad password" (Sub Status `0xC000006A`)
3. **Compromise** — one successful Logon Type 3 / NTLM v2 logon as `Bob` from `192.168.10.250` at 08:58:20 AM
4. **Tool verification** — cross-checked against the attack tools' own output and found both unreliable (Crowbar over-reported success; Hydra's RDP module failed to connect), confirming the event log as the correct source of truth

---

## Findings

- The attack was clearly attributable to a single host (`192.168.10.250` / `kali`) through the Workstation Name and Source Network Address fields present on every 4625/4624 event.
- NTLM Sub Status codes distinguished username-resolution failures from password failures, narrowing an analyst's focus during triage.
- **Crowbar v0.4.2's RDP module reported false positives**, logging `RDP-SUCCESS` for every password attempted (22/22) regardless of correctness. This is a known limitation where the tool validates RDP session negotiation rather than actual credential acceptance.
- **Hydra v9.7's RDP module**, used as a cross-check, failed to establish a connection for any attempt — its own documentation labels the module "experimental."
- The Windows Security event log, collected independently via Splunk, was the only reliable source of truth: it showed exactly one successful authentication against 26 failed attempts from the attacking host.
- The target account (`bob`) had no account lockout policy in effect, allowing unlimited password attempts with no slowdown or block.

---

## Mitigations / Next Steps

- **Account lockout policy:** Lock an account after a small number of failed attempts (e.g., 5 in 10 minutes) to limit brute-force viability.
- **MFA:** Would prevent a successful logon even with a correctly guessed password.
- **Splunk detection rule**, designed against this lab's observed pattern:

```spl
index=endpoint source="WinEventLog:Security" EventCode=4625
| bin _time span=1m
| stats count by _time, Source_Network_Address
| where count >= 5
```

This alert fires on 5+ failed logons from a single source within one minute.

- **MITRE ATT&CK mapping:** This attack maps to [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/), specifically T1110.001 (Password Guessing).
- **Future improvement:** Build a Splunk dashboard panel visualizing failed-logon volume by source IP in real time; test the alert above by re-running the attack after enabling an account lockout policy; and evaluate a third RDP brute-force tool to get a console output that matches the event log one-to-one.

---

## Tools Used

- Kali Linux (Crowbar v0.4.2, Hydra v9.7)
- Windows 10
- Splunk Enterprise 10.6.0.5
- SPL (Search Processing Language)
