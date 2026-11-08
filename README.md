# Splunk Detection Lab: RDP Brute Force Detection

A home lab that simulates RDP brute force attacks against a domain-joined Windows client and detects them in Splunk using Windows Security event logs.

<img width="872" height="817" alt="NetworkDiagram" src="https://github.com/user-attachments/assets/838e1df2-90c2-4d13-a824-728d0a1b0778" />


## Lab Environment

| Machine | IP Address | Role |
|---|---|---|
| Splunk Server | 192.168.10.10 | Log collection and search (web UI on port 8000) |
| Active Directory (Domain Controller) | 192.168.10.7 | Domain controller; Splunk Universal Forwarder and Sysmon installed |
| Windows 10 | 192.168.10.40 | Domain-joined client (`Bob-Win.Elidsi.local`); Splunk Universal Forwarder and Sysmon installed |
| Kali Linux | 192.168.10.250 | Attacker machine |

- **Domain:** Eli.dsi
- **Network:** 192.168.10.0/24, connected through a virtual switch with a gateway to the internet

## Architecture

The Windows 10 client is joined to the `Eli.dsi` Active Directory domain, so it authenticates against the domain controller (192.168.10.7) like a typical corporate workstation. Both the domain controller and the Windows 10 client run the **Splunk Universal Forwarder** and **Sysmon**, forwarding logs to the Splunk server over **port 9997**.

On the Windows 10 client, the forwarder is configured to collect:

<img width="570" height="644" alt="Screenshot 2026-11-07 021525" src="https://github.com/user-attachments/assets/c88b29ba-958b-4d53-ac0b-f9f0edce8086" />



Local audit policy was confirmed with `auditpol /get /category:"Logon/Logoff"`, which showed **Logon** auditing set to **Success and Failure** — the setting required for Event ID 4625 to be generated and captured.

<img width="511" height="256" alt="lab-configuration" src="https://github.com/user-attachments/assets/1fe382c8-951b-4c1f-8e07-af03de267faf" />

## Attacks Simulated

Both attacks targeted RDP (port 3389) on the Windows 10 client (192.168.10.40) from Kali (192.168.10.250), attempting to authenticate as the user `bob`.

### Attempt 1: Crowbar

```
crowbar -b rdp -u bob -C passwords.txt -s 192.168.10.40/32
```

<img width="1896" height="859" alt="Screenshot 2026-11-07 105721" src="https://github.com/user-attachments/assets/5e536049-cf5f-459a-a77e-1ac08549e637" />




Crowbar reported `RDP-SUCCESS` for every password in the list, including obviously wrong ones (`123456`, `password`, `qwerty`). This is a known false-positive behavior in Crowbar's RDP module — it can report success when the connection step completes, even without valid credentials. A second run used the domain-qualified username `elidsi\bob` and produced the same false-positive pattern.

Because the console output couldn't be trusted, it was not used to judge success or failure — see Detection below.

### Attempt 2: Hydra

```
hydra -l bob -P passwords.txt rdp://192.168.10.40 -t 4 -W 3
```
<img width="1900" height="909" alt="Screenshot 2026-11-07 115735" src="https://github.com/user-attachments/assets/ad454c8f-8cee-4890-aa56-4f71a5dc4254" />


Hydra ran 22 attempts and reported **0 valid passwords found**. It flagged one combination (`bob:rockyou`) as "might be valid but account not active for remote desktop," then failed to establish the connection with a FreeRDP error. Hydra's own output marks its RDP module as experimental.

### Why the Windows Security log was the deciding source

Neither tool's console output was reliable: Crowbar over-reported success, and Hydra's RDP module failed to connect. The Windows Security log, collected independently by Sysmon and the Universal Forwarder, was used as the authoritative record of what actually happened.

## Detection and Analysis

All queries below run against `index=endpoint`, `source="WinEventLog:Security"`.

**1. Identifying the attack source and target accounts**

```spl
index=endpoint source="WinEventLog:Security" EventCode=4625
| rex "Source Network Address:\s+(?<src_ip>\S+)"
| rex "Sub Status:\s+(?<sub_status>\S+)"
| rex "Account For Which Logon Failed:\s+Security ID:\s+\S+\s+Account Name:\s+(?<target_user>\S+)"
| search src_ip="192.168.10.250"
| stats count by target_user, sub_status
```
<img width="1906" height="827" alt="Screenshot 2026-11-07 114850" src="https://github.com/user-attachments/assets/e6f71e71-f7bc-44c3-b5cc-6882e2654607" />


Results (181 total failed logon events from 192.168.10.250):

| target_user | sub_status | count | meaning |
|---|---|---|---|
| bob | 0xC0000064 | 112 | user name does not exist |
| bob | 0xC000006A | 4 | user name correct, password wrong |
| elidsibob | 0xC0000064 | 65 | user name does not exist |

The `elidsibob` entries came from the Crowbar run that used `elidsi\bob` as the login — Windows logged the domain-qualified name as a single literal account name, which doesn't match a real account and so always failed with "no such user." This also means Crowbar's domain-prefixed attempt would never have succeeded even with the correct password, which is a useful finding about credential formatting, separate from the tool's false-positive console output.

**2. Confirming the source and total event count**

```spl
index=endpoint source="WinEventLog:Security" EventCode=4625
| rex "Source Network Address:\s+(?<src_ip>\S+)"
| stats count by src_ip
| sort - count
```

All 4625 events in the search window trace back to a single source: **192.168.10.250**.

**3. Attack pace**

A one-minute window (9:25–9:26 AM) showed 12 failed logon events, consistent with the rapid, automated attempts generated by Crowbar and Hydra rather than manual login tries.

**Example raw event:**

<img width="1478" height="834" alt="Screenshot 2026-11-07 101921" src="https://github.com/user-attachments/assets/8fd4a39e-b4d2-495f-9165-f1ff011fe93e" />


```
EventCode=4625
ComputerName=Bob-Win.Elidsi.local
Account Name: bob
Account Domain: ELIDSI
Logon Type: 3
Failure Reason: Unknown user name or bad password.
Status: 0xC000006D
Sub Status: 0xC000006A
Workstation Name: kali
Source Network Address: 192.168.10.250
Logon Process: NtLmSsp
Authentication Package: NTLM
```

Logon Type 3 (network) and the NTLM authentication package are consistent with an RDP/network logon attempt rather than an interactive one.

## Results

- **Source of the attack:** 192.168.10.250 (Kali), confirmed independently of either attack tool's own output
- **Total failed logon events (4625) analyzed:** 181, across two account name variants (`bob`, `elidsibob`)
- **Valid credentials found:** None confirmed. Crowbar's reported successes were false positives; Hydra found 0 valid passwords and failed to connect
- **Successful logon (Event ID 4624) for bob:** Not observed in the searches run so far

## Tools Used

- Splunk Enterprise
- Splunk Universal Forwarder
- Sysmon
- Windows Server (Active Directory)
- Windows 10
- Kali Linux
- Hydra
- Crowbar
- Atomic Red Team (installed for future technique simulation)
- draw.io (network diagram)

## What I Learned

- Joining a Windows 10 client to an Active Directory domain
- Installing and configuring Splunk Universal Forwarders to collect Security, System, Application, and Sysmon logs
- Verifying audit policy (`auditpol`) to confirm the logs needed for detection are actually being generated
- Using `rex` in SPL to extract fields (source IP, target username, NTLM sub-status) from raw Windows event text
- Reading NTLM failure sub-status codes (0xC0000064 vs. 0xC000006A) to distinguish "no such user" from "wrong password"
- Not trusting an attack tool's own console output — Crowbar's RDP module reported false-positive successes, and Hydra's RDP module failed to connect; the Windows Security log was the only reliable source of truth
- How a domain-qualified login (`elidsi\bob`) can be logged as a different literal account name than the plain username

## Next Steps

- Search for Event ID 4624 to confirm whether any attempt actually succeeded
- Build a Splunk alert that fires on a threshold of failed logons from one source
- Detect a 4625-then-4624 pattern (failed attempts followed by a success) from the same source
- Use Atomic Red Team to simulate additional attack techniques and map them to MITRE ATT&CK
