<div align="center">
  <img src="https://github.com/uzairshahidgithub/Ransomware-IR-Purple-Team-Exercise-Lab/blob/main/Daigram%20Map.png?raw=true" 
       alt="MITRE Lab Diagram" 
       width="600"/>
</div>

**Snapshot your Windows VM before starting Phase 1.** You will need to restore it after the exercise.

---

## MITRE ATT&CK Coverage

| Phase | Tactic | Technique |
|---|---|---|
| Initial Access | TA0001 | T1566.001: Spearphishing Attachment |
| Execution | TA0002 | T1059.001: PowerShell |
| Defence Evasion | TA0005 | T1562.001: Disable Security Tools |
| Discovery | TA0007 | T1083: File and Directory Discovery |
| Lateral Movement | TA0008 | T1021.002: SMB Admin Shares |
| Impact | TA0040 | T1486: Data Encrypted for Impact |
| Impact | TA0040 | T1490: Inhibit System Recovery |
| Impact | TA0040 | T1489: Service Stop |

---

## Free Online Practice Labs (Complete Before or After Main Lab)

These are selected specifically for ransomware IR skill-building. All are free tier.

### TryHackMe Rooms

| Room | URL | Skill Built |
|---|---|---|
| **Conti** | [tryhackme.com/room/conti](https://tryhackme.com/room/conti) | Conti ransomware PCAP + memory analysis workflow |
| **Unattended** | [tryhackme.com/room/unattended](https://tryhackme.com/room/unattended) | Windows forensics timeline reconstruction post-ransomware |
| **Masterminds** | [tryhackme.com/room/masterminds](https://tryhackme.com/room/masterminds) | Multi-stage attack investigation with ransomware final stage |
| **Carnage** | [tryhackme.com/room/carnage](https://tryhackme.com/room/carnage) | PCAP analysis of full malware delivery and execution chain |
| **Benign** | [tryhackme.com/room/benign](https://tryhackme.com/room/benign) | Wazuh-based investigation of compromised Windows host |

**Recommended order:** Conti → Carnage → Unattended → Masterminds → Benign

### CyberDefenders Challenges (Free Tier)

| Challenge | URL | Skill Built |
|---|---|---|
| **Seized** | [cyberdefenders.org/blueteam-ctf-challenges/seized](https://cyberdefenders.org/blueteam-ctf-challenges/seized) | Full disk image forensics post-ransomware infection |
| **PacketMaze** | [cyberdefenders.org/blueteam-ctf-challenges/packetmaze](https://cyberdefenders.org/blueteam-ctf-challenges/packetmaze) | Network forensics of exfiltration before encryption |

---

## Phase 0: Setup (20 Minutes)

### 0.1: Snapshot Windows VM

```powershell
# Before anything else: snapshot your victim VM
# In VirtualBox
VBoxManage snapshot "Windows10-Victim" take "pre-ransomware-lab" --description "Clean state before DEAD CANARY"

# In VMware: VM → Snapshot → Take Snapshot → "pre-ransomware-lab"
```

### 0.2: Verify Prerequisites on Windows Victim VM

```powershell
# Run as Administrator on Windows Victim VM

# Confirm Sysmon is running
Get-Service Sysmon64 | Select-Object Name, Status

# Confirm Wazuh agent is enrolled and sending logs
Get-Service OssecSvc | Select-Object Name, Status

# Confirm internet access (for Atomic Red Team install)
Test-NetConnection -ComputerName github.com -Port 443

# Create a test directory structure to simulate a user's file collection
# Atomic Red Team encryption tests need target files to work with
New-Item -Path "C:\LabVictimFiles" -ItemType Directory -Force
1..50 | ForEach-Object {
    $type = @("docx","xlsx","pdf","txt","jpg") | Get-Random
    $name = "Document_$_.$type"
    "This is simulated victim file content number $_" | Out-File "C:\LabVictimFiles\$name"
}
Write-Host "Created 50 victim files in C:\LabVictimFiles"
Get-ChildItem "C:\LabVictimFiles" | Measure-Object | Select-Object Count
```

### 0.3: Install Atomic Red Team

Atomic Red Team is an open source framework maintained by Red Canary. Each "atomic test" is a safe, documented simulation of a single MITRE ATT&CK technique: no actual malware, no real damage beyond what the test specifies and no network callbacks to external infrastructure.

```powershell
# Run as Administrator

# Temporarily set execution policy for install (will restore)
Set-ExecutionPolicy Bypass -Scope Process -Force

# Install Atomic Red Team PowerShell module
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

# Verify install
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
Get-Help Invoke-AtomicTest

# Confirm ransomware-related atomics are available
Invoke-AtomicTest T1486 -ShowDetails
Invoke-AtomicTest T1490 -ShowDetails
Invoke-AtomicTest T1489 -ShowDetails
```

---

## Phase 1: Red Team: Ransomware Simulation (40 Minutes)

> **Red Hat on.** You are now simulating an attacker who has already achieved initial access and is executing the ransomware kill chain. Work through each TTP in sequence, exactly as a real ransomware operator would.

### Task 1.1: Disable Defences (T1562.001)

Ransomware operators disable Windows Defender, Firewall and backup agents before encryption to prevent interruption and removal.

```powershell
# Import module
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"

# T1562.001: Impair Defences: Disable Windows Defender
Invoke-AtomicTest T1562.001 -TestNumbers 1,2 -GetPrereqs
Invoke-AtomicTest T1562.001 -TestNumbers 1,2

# Manual simulation (also generates Sysmon + Windows Security logs)
# Disable Defender real-time monitoring
Set-MpPreference -DisableRealtimeMonitoring $true

# Disable Windows Firewall
netsh advfirewall set allprofiles state off

# Document what Sysmon Event ID is generated by this action:
# Expected: Event ID 13 (RegistryValueSet) + Event ID 1 (Process Creation for netsh)
```

---

### Task 1.2: Inhibit System Recovery (T1490)

Shadow copies are Windows' built-in rollback mechanism. Ransomware deletes them first: before encryption: to prevent recovery without paying.

```powershell
# T1490: Inhibit System Recovery: Delete Shadow Copies
# This is one of the clearest ransomware behavioural signatures

Invoke-AtomicTest T1490 -TestNumbers 1
# Atomic 1: vssadmin delete shadows /all /quiet

Invoke-AtomicTest T1490 -TestNumbers 3
# Atomic 3: wmic shadowcopy delete

# Manual: also run directly to ensure log generation
vssadmin delete shadows /all /quiet 2>&1
wmic shadowcopy delete

# Disable Windows Backup and recovery boot options
bcdedit /set {default} recoveryenabled No
bcdedit /set {default} bootstatuspolicy ignoreallfailures

# Verify shadow copies are gone
vssadmin list shadows
# Expected output: "No items found that satisfy the query"
```

**This action generates Event ID 4688 (process creation) with `vssadmin.exe` and `wmic.exe`: one of the highest-confidence ransomware indicators in Windows event logs.**

---

### Task 1.3: Service Termination (T1489)

Ransomware stops database services, backup agents and email servers to release file locks: locked files cannot be encrypted.

```powershell
# T1489: Service Stop
Invoke-AtomicTest T1489 -TestNumbers 1

# Manual simulation of what ransomware like Conti/LockBit does
$services_to_stop = @(
    "MSSQLSERVER",      # SQL Server
    "SQLSERVERAGENT",   # SQL Agent
    "MSSQLFDLauncher",  # SQL Full-Text
    "MSDTC",            # Distributed Transaction
    "W3SVC",            # IIS
    "MSExchangeIS",     # Exchange
    "vss",              # Volume Shadow Service
    "wbengine"          # Windows Backup Engine
)

foreach ($svc in $services_to_stop) {
    try {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Write-Host "[STOPPED] $svc"
    } catch {
        Write-Host "[NOT FOUND] $svc (expected in lab: no SQL/Exchange installed)"
    }
}

# Net stop commands (also generates detectable logs)
net stop "Volume Shadow Copy" /y
net stop "Windows Backup" /y
```

---

### Task 1.4: File Discovery (T1083)

Before encrypting, ransomware enumerates drives and files to identify high-value targets and calculate ransom amounts.

```powershell
# T1083: File and Directory Discovery
Invoke-AtomicTest T1083 -TestNumbers 1,2

# Simulate ransomware file enumeration targeting document types
$extensions = @("*.docx","*.xlsx","*.pdf","*.txt","*.jpg","*.pptx","*.csv","*.db","*.sql","*.bak")
$target_dirs = @("C:\Users","C:\LabVictimFiles","C:\inetpub","D:\")

foreach ($dir in $target_dirs) {
    foreach ($ext in $extensions) {
        Get-ChildItem -Path $dir -Filter $ext -Recurse -ErrorAction SilentlyContinue |
            Select-Object FullName, Length, LastWriteTime |
            Export-Csv -Path "C:\Windows\Temp\filelist.csv" -Append -NoTypeInformation
    }
}

Write-Host "File discovery complete. Target list written to C:\Windows\Temp\filelist.csv"
(Import-Csv "C:\Windows\Temp\filelist.csv").Count
```

---

### Task 1.5: Data Encrypted for Impact (T1486)

```powershell
# T1486: Data Encrypted for Impact
# Atomic Red Team test: encrypts ONLY the test files in C:\LabVictimFiles
# Does NOT encrypt system files or user profile

Invoke-AtomicTest T1486 -TestNumbers 1
# This runs a safe XOR-based file transformation on test files only

# Drop simulated ransom note (real ransomware signature)
$ransom_note = @"
YOUR FILES HAVE BEEN ENCRYPTED
================================
All your documents, databases and backups have been encrypted
with AES-256 + RSA-2048. Only we have the decryption key.

To recover your files:
1. Do NOT attempt to restore from backup: backups have been wiped
2. Contact: deadcanary@protonmail.com
3. Include your unique ID: DC-$(Get-Random -Minimum 100000 -Maximum 999999)
4. Payment: 2.5 BTC to wallet: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2

Files recovered within 48 hours of payment.
Every hour of delay adds 10% to the ransom.

THIS IS A CIPHER LAB SIMULATION: NOT REAL RANSOMWARE
"@

# Drop note in multiple locations (Conti/LockBit pattern)
$note_locations = @(
    "C:\LabVictimFiles\!!!READ_ME!!!.txt",
    "C:\Users\Public\Desktop\!!!READ_ME!!!.txt",
    "C:\README.txt"
)

foreach ($loc in $note_locations) {
    $ransom_note | Out-File $loc -Encoding UTF8
    Write-Host "Ransom note dropped: $loc"
}
```

> **Red team work complete.** Take a screenshot of the terminal showing all five phases executed. Switch to blue hat.

---

## Phase 2: Blue Team: Detection & Alert Triage (30 Minutes)

> **Blue Hat on.** You are the on-call SOC analyst. Wazuh has fired alerts. Your job is to triage, investigate and open a TheHive case with structured findings.

### Task 2.1: Triage Wazuh Alerts

Navigate to Wazuh Dashboard → **Threat Hunting → Security Alerts**

Apply these filters in sequence and document what you find at each step:

```
# Filter 1: Shadow copy deletion (highest confidence ransomware indicator)
rule.description: *shadow* OR data.win.eventdata.commandLine: *vssadmin*

# Filter 2: Service termination events
data.win.system.eventID: 7036 OR data.win.system.eventID: 7040

# Filter 3: File write bursts (many files modified in short period)
rule.groups: sysmon AND data.win.system.eventID: 11
# Sort by @timestamp, look for rapid sequential file creation in C:\LabVictimFiles

# Filter 4: Ransom note detection (file named README or READ_ME)
data.win.eventdata.targetFilename: (*READ_ME* OR *README* OR *DECRYPT*)

# Filter 5: bcdedit execution (recovery disabling)
data.win.eventdata.commandLine: *bcdedit* AND data.win.eventdata.commandLine: *recoveryenabled*

# Filter 6: netsh firewall disable
data.win.eventdata.commandLine: *advfirewall* AND data.win.eventdata.commandLine: *off*
```

**Triage Priority Matrix: complete this for your report:**

| Alert | Rule Fired | Confidence | Priority |
|---|---|---|---|
| vssadmin delete shadows | | | |
| bcdedit recovery disabled | | | |
| Ransom note file created | | | |
| Defender disabled | | | |
| Mass file modification | | | |
| Service termination | | | |

---

### Task 2.2: Open TheHive Case

```bash
# Via TheHive web UI (http://SYSTEM2_IP:9000) or via API

curl -s -u admin@thehive.local:secret \
  -X POST "http://192.168.1.20:9000/api/v1/case" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "DEAD CANARY: Active Ransomware Incident on WIN-VICTIM",
    "description": "Wazuh alerts triggered at [TIME]. Shadow copy deletion, bcdedit modification and ransom note drop detected on Windows agent WIN-VICTIM. Possible ransomware execution in progress.",
    "severity": 3,
    "tlp": 2,
    "pap": 2,
    "tags": ["ransomware","T1486","T1490","T1562","windows","active-incident"],
    "tasks": [
      {"title": "Isolate affected endpoint", "group": "containment"},
      {"title": "Acquire memory image", "group": "forensics"},
      {"title": "Identify patient zero and initial access vector", "group": "investigation"},
      {"title": "Extract IOCs and push to MISP", "group": "intelligence"},
      {"title": "Identify scope of encryption", "group": "impact"},
      {"title": "Restore from last known good backup", "group": "recovery"}
    ]
  }'
```

**Add observables to the case:**

```bash
# Add hostname
curl -s -u admin@thehive.local:secret \
  -X POST "http://192.168.1.20:9000/api/v1/case/CASE_ID/observable" \
  -H "Content-Type: application/json" \
  -d '{"dataType":"hostname","data":"WIN-VICTIM","tags":["victim"],"ioc":false}'

# Add ransom note hash
$hash = (Get-FileHash "C:\LabVictimFiles\!!!READ_ME!!!.txt" -Algorithm SHA256).Hash
# Add this hash as an observable of type "hash"

# Add any C2 domains or IPs found in ransom note
```

---

### Task 2.3: Timeline Reconstruction (Wazuh)

Build a precise timeline of the attack in Wazuh. This is the most important skill in incident response: every containment and recovery decision depends on knowing the exact sequence of events.

```
# In Wazuh Dashboard → Threat Hunting → Events
# Set time range to: last 2 hours
# Filter: agent.name: WIN-VICTIM
# Sort: @timestamp ascending

Required timeline columns:
- @timestamp
- data.win.system.eventID
- data.win.eventdata.image (process)
- data.win.eventdata.commandLine
- data.win.eventdata.targetFilename
- rule.description
```

**Minimum viable timeline: document all six rows:**

```
[TIME T+00:00] Defender real-time monitoring disabled
               Process: powershell.exe
               Command: Set-MpPreference -DisableRealtimeMonitoring $true
               EventID: 13 (Registry modification)
               Sysmon: YES | Wazuh Alert: YES/NO

[TIME T+00:XX] Shadow copies deleted
               Process: vssadmin.exe / wmic.exe
               Command: vssadmin delete shadows /all /quiet
               EventID: 4688 (Process Creation)
               Sysmon: YES | Wazuh Alert: YES/NO

[TIME T+00:XX] Recovery boot options disabled
               Process: bcdedit.exe
               Command: bcdedit /set {default} recoveryenabled No
               EventID: 4688
               Sysmon: YES | Wazuh Alert: YES/NO

[TIME T+00:XX] Services stopped
               Process: net.exe / sc.exe
               EventID: 7036 (Service state change)
               Sysmon: YES | Wazuh Alert: YES/NO

[TIME T+00:XX] File discovery executed
               Process: powershell.exe / Get-ChildItem
               Output written to: C:\Windows\Temp\filelist.csv
               EventID: 1 (Process Creation) + 11 (File Created)
               Sysmon: YES | Wazuh Alert: YES/NO

[TIME T+00:XX] Ransom notes dropped
               Process: powershell.exe / Out-File
               Files: C:\LabVictimFiles\!!!READ_ME!!!.txt
               EventID: 11 (File Created)
               Sysmon: YES | Wazuh Alert: YES/NO
```

> **Flag 1:** Complete timeline with all six events documented and Wazuh alert Y/N for each. Record: `CIPHER{timeline_complete_<total_alerts_fired>_detected}`

---

## Phase 3: DFIR: Memory and Disk Forensics (40 Minutes)

### Task 3.1: Acquire Memory Image

```bash
# On Windows Victim VM: acquire memory dump for analysis
# Using winpmem (free, open source memory acquisition)

# Download winpmem
Invoke-WebRequest -Uri "https://github.com/Velocidex/WinPmem/releases/latest/download/winpmem_mini_x64_rc2.exe" -OutFile "C:\Tools\winpmem.exe"

# Acquire full memory dump
C:\Tools\winpmem.exe C:\LabOutput\memory_victim.raw

# Verify acquisition
Get-Item "C:\LabOutput\memory_victim.raw" | Select-Object Name, Length
```

```bash
# Transfer to analysis machine (System 1 / Kali)
scp analyst@WIN_VICTIM_IP:"C:/LabOutput/memory_victim.raw" ~/dead_canary/forensics/
```

### Task 3.2: Memory Analysis with Volatility3

```bash
mkdir -p ~/dead_canary/forensics

# Install Volatility3 if not already installed
pip3 install volatility3

# Confirm image info
python3 -m volatility3.vol -f ~/dead_canary/forensics/memory_victim.raw windows.info

# List running processes at time of capture
python3 -m volatility3.vol \
  -f ~/dead_canary/forensics/memory_victim.raw \
  windows.pslist \
  > ~/dead_canary/forensics/pslist.txt

cat ~/dead_canary/forensics/pslist.txt
```

**Processes to look for in the output: document what you find:**

```bash
# Filter for ransomware-related processes
grep -Ei "vssadmin|wmic|bcdedit|powershell|cmd|net\.exe|sc\.exe" \
  ~/dead_canary/forensics/pslist.txt

# Check process tree: identify unusual parent-child relationships
python3 -m volatility3.vol \
  -f ~/dead_canary/forensics/memory_victim.raw \
  windows.pstree
```

```bash
# Examine command lines of suspicious processes
python3 -m volatility3.vol \
  -f ~/dead_canary/forensics/memory_victim.raw \
  windows.cmdline \
  | grep -Ei "shadow|bcdedit|disable|encrypt|delete"
```

```bash
# Check network connections at time of memory capture
# Ransomware often has an active C2 connection for key exchange
python3 -m volatility3.vol \
  -f ~/dead_canary/forensics/memory_victim.raw \
  windows.netstat \
  > ~/dead_canary/forensics/netstat.txt

# Filter for external connections (non-RFC1918)
grep -v "127.0.0\|10\.\|192\.168\.\|172\." ~/dead_canary/forensics/netstat.txt | \
  grep -Ei "ESTABLISHED|CLOSE_WAIT"
```

```bash
# Extract registry hives from memory for persistence analysis
python3 -m volatility3.vol \
  -f ~/dead_canary/forensics/memory_victim.raw \
  windows.registry.printkey \
  --key "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" \
  > ~/dead_canary/forensics/registry_run_keys.txt

cat ~/dead_canary/forensics/registry_run_keys.txt
# Look for: unexpected executables, base64 encoded commands, temp path references
```

```bash
# Scan memory for known malicious patterns with YARA
# Create a ransomware indicator YARA rule
cat > ~/dead_canary/yara/ransomware_indicators.yar << 'EOF'
rule ransomware_behavioral_indicators
{
    meta:
        description = "Generic ransomware memory artefacts"
        author      = "CIPHER Lab"
        mitre       = "T1486"

    strings:
        // Shadow copy deletion commands (found in memory of ransomware process)
        $vss1 = "vssadmin delete shadows" ascii nocase
        $vss2 = "shadowcopy delete" ascii nocase
        $vss3 = "wbadmin delete catalog" ascii nocase

        // Recovery disabling
        $rec1 = "recoveryenabled No" ascii nocase
        $rec2 = "bootstatuspolicy ignoreallfailures" ascii nocase

        // Ransom note markers
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii nocase
        $note2 = "BTC" ascii nocase
        $note3 = "protonmail" ascii nocase
        $note4 = "decryption key" ascii nocase

    condition:
        2 of ($vss*) or 2 of ($note*)
}
EOF

# Scan memory dump with YARA
yara ~/dead_canary/yara/ransomware_indicators.yar \
  ~/dead_canary/forensics/memory_victim.raw
```

---

### Task 3.3: Disk Artefact Analysis

```bash
# On Windows Victim VM: collect key artefacts before snapshot restore
# Using Eric Zimmerman Tools (EZ Tools): free forensic suite

# Download EZ Tools
Invoke-WebRequest -Uri "https://ericzimmermandotcom.azurewebsites.net/GetAllTools.ps1" -OutFile "C:\Tools\GetEZTools.ps1"
Set-ExecutionPolicy Bypass -Scope Process
.\GetEZTools.ps1

# Parse Windows Event Logs for the attack period
# Focus on Security log (4688 process, 7036 service) and Sysmon log

# Export relevant event log entries
wevtutil qe Security /q:"*[System[(EventID=4688)]]" /f:xml /rd:true /c:100 > C:\LabOutput\security_4688.xml
wevtutil qe "Microsoft-Windows-Sysmon/Operational" /f:xml /rd:true /c:200 > C:\LabOutput\sysmon_events.xml
```

```bash
# Parse Windows Prefetch (shows executed programs + execution count + last run time)
# Prefetch for vssadmin, bcdedit, net.exe confirms they ran even after log clearing attempts

& "C:\Tools\PECmd.exe" \
  -d "C:\Windows\Prefetch" \
  --csv "C:\LabOutput\" \
  --csvf prefetch_results.csv

Import-Csv "C:\LabOutput\prefetch_results.csv" |
  Where-Object { $_.ExecutableName -match "vssadmin|bcdedit|wmic|net\.exe" } |
  Select-Object ExecutableName, LastRun, RunCount |
  Sort-Object LastRun -Descending
```

```bash
# Check for ransom note across all drives
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match "READ_ME|README|DECRYPT|HELP|HOW_TO" } |
  Select-Object FullName, LastWriteTime, Length
```

```bash
# Identify encrypted files by extension change (ransomware renames files)
# Check for unknown extensions added during attack window
Get-ChildItem "C:\LabVictimFiles" |
  Group-Object Extension |
  Sort-Object Count -Descending |
  Select-Object Name, Count
# Any extension you did not create = ransomware-appended extension
```

> **Flag 2:** Screenshot showing Volatility3 pslist output with relevant processes highlighted + prefetch confirmation. Record: `CIPHER{volatility_confirms_<process_name>_executed}`

---

## Phase 4: Containment and Recovery (30 Minutes)

### Task 4.1: Immediate Containment

**Isolation via Wazuh Active Response:**

```bash
# From Wazuh Manager: isolate the agent (blocks all traffic except Wazuh comms)
# This is the fastest containment action for a confirmed ransomware case

curl -k -u admin:SecretPassword \
  -X PUT "https://localhost:55000/active-response" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "firewall-drop",
    "arguments": ["WIN-VICTIM-IP"],
    "agent_ids": ["WIN-VICTIM-AGENT-ID"]
  }'

# Verify isolation
# From victim VM: ping 8.8.8.8  ← should fail
# From victim VM: ping Wazuh Manager IP ← should succeed (Wazuh comms preserved)
```

**Manual network isolation (if Wazuh active response is unavailable):**

```powershell
# On victim VM: cut all network while preserving management access
# Emergency isolation: complete network cut
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
# Note: this also cuts Wazuh: only do this if active response is unavailable
```

---

### Task 4.2: IOC Extraction and MISP Push

```bash
# Extract all IOCs from the investigation

cat > ~/dead_canary/intelligence/iocs.json << 'EOF'
{
  "incident": "DEAD CANARY",
  "date": "2024-01-15",
  "iocs": [
    {"type": "filename", "value": "!!!READ_ME!!!.txt", "context": "Ransom note filename"},
    {"type": "filename", "value": "filelist.csv", "context": "Attacker file enumeration output"},
    {"type": "path", "value": "C:\\Windows\\Temp\\filelist.csv", "context": "Staging path"},
    {"type": "command", "value": "vssadmin delete shadows /all /quiet", "context": "Shadow copy deletion"},
    {"type": "command", "value": "bcdedit /set {default} recoveryenabled No", "context": "Recovery disable"},
    {"type": "email", "value": "deadcanary@protonmail.com", "context": "Ransom contact (simulated)"},
    {"type": "registry", "value": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", "context": "Defender disabled"},
    {"type": "mitre", "value": "T1486", "context": "Data Encrypted for Impact"},
    {"type": "mitre", "value": "T1490", "context": "Inhibit System Recovery"},
    {"type": "mitre", "value": "T1562.001", "context": "Disable Security Tools"}
  ]
}
EOF

cat ~/dead_canary/intelligence/iocs.json
```

```bash
# Push IOCs to MISP via API
MISP_URL="http://192.168.1.20"
MISP_KEY="YOUR_MISP_API_KEY"

curl -s -H "Authorization: $MISP_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -X POST "$MISP_URL/events" \
  -d '{
    "info": "DEAD CANARY: Ransomware Simulation IOCs",
    "distribution": 0,
    "threat_level_id": 1,
    "analysis": 2,
    "Attribute": [
      {"type": "filename", "value": "!!!READ_ME!!!.txt", "category": "Artifacts dropped"},
      {"type": "text", "value": "vssadmin delete shadows /all /quiet", "category": "External analysis"}
    ]
  }'
```

---

### Task 4.3: Recovery Procedure

```powershell
# RECOVERY STEPS: document each one in your IR report

# Step 1: Restore from snapshot (lab environment)
# VirtualBox
VBoxManage snapshot "Windows10-Victim" restore "pre-ransomware-lab"

# In production: this step is replaced by:
# - Restore from last verified clean backup
# - Verify backup integrity before restore (ransomware may have infected backup agents)
# - Restore to isolated network for verification before production reconnect

# Step 2: After restore: verify shadow copies exist
vssadmin list shadows
# Should show pre-attack shadow copies restored with the snapshot

# Step 3: Re-enable security controls
Set-MpPreference -DisableRealtimeMonitoring $false
netsh advfirewall set allprofiles state on

# Step 4: Change all credentials
# In lab: reset the lab VM admin password
net user Administrator NewSecurePassword123!

# Step 5: Verify Sysmon and Wazuh agent are healthy post-restore
Get-Service Sysmon64,OssecSvc | Select-Object Name,Status
```

---

## Phase 5: Purple Team Debrief & Gap Analysis (20 Minutes)

This is the highest-value phase and the one most teams skip. Do not skip it.

### Task 5.1: Complete the Gap Analysis Table

For every TTP simulated, document whether it was detected, what detected it and what was missed.

```
============================================================
PURPLE TEAM GAP ANALYSIS: DEAD CANARY
Date: [DATE]
Red Team: [YOUR NAME]      Blue Team: [YOUR NAME / PARTNER]
============================================================

TTP 1: T1562.001: Disable Security Tools (Defender)
  Simulated:     YES
  Wazuh Detected: YES / NO
  Detection Method: [which rule / event ID]
  Time to Detection: [minutes from execution to alert]
  Gap Identified: [if NO: why not? what log source was missing?]
  Remediation: [new Wazuh rule? log source addition?]

TTP 2: T1490: Inhibit System Recovery (Shadow Copy Deletion)
  Simulated:     YES
  Wazuh Detected: YES / NO
  Detection Method:
  Time to Detection:
  Gap Identified:
  Remediation:

TTP 3: T1489: Service Stop
  Simulated:     YES
  Wazuh Detected: YES / NO
  Detection Method:
  Time to Detection:
  Gap Identified:
  Remediation:

TTP 4: T1083: File Discovery (filelist.csv creation)
  Simulated:     YES
  Wazuh Detected: YES / NO
  Detection Method:
  Time to Detection:
  Gap Identified:
  Remediation:

TTP 5: T1486: Data Encrypted for Impact
  Simulated:     YES
  Wazuh Detected: YES / NO
  Detection Method:
  Time to Detection:
  Gap Identified:
  Remediation:

TTP 6: Ransom Note Drop (file creation)
  Simulated:     YES
  Wazuh Detected: YES / NO
  Detection Method:
  Time to Detection:
  Gap Identified:
  Remediation:

SUMMARY
--------
Total TTPs simulated:  6
Total TTPs detected:   [X]
Detection coverage:    [X/6 = X%]
Mean time to detect:   [avg minutes]
Critical gaps:         [list any TTP with NO detection]
============================================================
```

---

### Task 5.2: Write Detection Rules for Gaps

For every gap identified (a TTP that was NOT detected), write a Wazuh rule now.

**Template: add to `/var/ossec/etc/rules/local_rules.xml`:**

```xml
<!-- DEAD CANARY gap-fill rule: generated from purple team debrief -->
<!-- TTP: T1490: Shadow Copy Deletion via vssadmin -->
<rule id="100040" level="14">
    <if_sid>61603</if_sid>   <!-- Sysmon process creation -->
    <field name="data.win.eventdata.image" type="pcre2">(?i)vssadmin\.exe$</field>
    <field name="data.win.eventdata.commandLine" type="pcre2">(?i)(delete\s+shadows|resize\s+shadowstorage)</field>
    <description>CRITICAL: vssadmin shadow copy deletion: ransomware pre-encryption step</description>
    <mitre><id>T1490</id></mitre>
    <group>windows,ransomware,t1490,attack,high_confidence</group>
</rule>


<rule id="100041" level="14">
    <if_sid>61603</if_sid>
    <field name="data.win.eventdata.image" type="pcre2">(?i)wmic\.exe$</field>
    <field name="data.win.eventdata.commandLine" type="pcre2">(?i)shadowcopy\s+delete</field>
    <description>CRITICAL: wmic shadowcopy delete: alternate ransomware shadow copy removal method</description>
    <mitre><id>T1490</id></mitre>
    <group>windows,ransomware,t1490,attack,high_confidence</group>
</rule>


<rule id="100042" level="12">
    <if_sid>61603</if_sid>
    <field name="data.win.eventdata.image" type="pcre2">(?i)bcdedit\.exe$</field>
    <field name="data.win.eventdata.commandLine" type="pcre2">(?i)(recoveryenabled\s+no|bootstatuspolicy)</field>
    <description>CRITICAL: bcdedit boot recovery disabled: ransomware pre-encryption step</description>
    <mitre><id>T1490</id></mitre>
    <group>windows,ransomware,t1490,attack,high_confidence</group>
</rule>


<rule id="100043" level="12">
    <if_sid>61610</if_sid>   <!-- Sysmon file creation event -->
    <field name="data.win.eventdata.targetFilename" type="pcre2">(?i)(READ_ME|README|DECRYPT|HOW_TO|INSTRUCTIONS|RESTORE).*\.(txt|html|hta)$</field>
    <description>HIGH: Ransom note filename pattern detected: possible ransomware payload dropped</description>
    <mitre><id>T1486</id></mitre>
    <group>windows,ransomware,t1486,attack</group>
</rule>
```

> **Flag 3:** Gap analysis table completed with at least 4 rows + new detection rules written for identified gaps. Record: `CIPHER{purple_team_gap_<gap_count>_rules_added_<rule_count>}`

---

## Final Deliverables

| # | Item | Phase |
|---|---|---|
| 1 | Atomic Red Team execution screenshots (all 5 TTPs run) | Phase 1 |
| 2 | Wazuh alert triage table (all 6 TTPs, detected Y/N) | Phase 2 |
| 3 | TheHive case created with observables and tasks | Phase 2 |
| 4 | Attack timeline (all 6 events with timestamps) | Phase 2 |
| 5 | Volatility3: pslist, cmdline, netstat output | Phase 3 |
| 6 | YARA scan result on memory image | Phase 3 |
| 7 | Prefetch analysis confirming executed programs | Phase 3 |
| 8 | IOC JSON exported and pushed to MISP | Phase 4 |
| 9 | Recovery steps documented (snapshot restore + controls re-enabled) | Phase 4 |
| 10 | Purple Team Gap Analysis (complete table) | Phase 5 |
| 11 | Gap-fill detection rules written and loaded in Wazuh | Phase 5 |
| 12 | TryHackMe: Conti room completion screenshot | Online Labs |

---

## Final Incident Report Structure

```
INCIDENT REPORT: DEAD CANARY
==============================
Classification: HIGH: Confirmed Ransomware Execution (Simulated)
Analyst(s): [NAME]
Date: [DATE]

1. EXECUTIVE SUMMARY
   One-paragraph summary of what happened, what was affected and
   current status (contained / recovering / resolved).

2. DETECTION TIMELINE
   Paste your completed 6-row timeline from Task 2.3

3. FORENSIC FINDINGS
   - Memory analysis: processes found, network connections, registry keys
   - Disk analysis: prefetch evidence, ransom note locations, encrypted files
   - Key artefact: C:\Windows\Temp\filelist.csv (attacker's target list)

4. ATTACK CHAIN (MITRE ATT&CK)
   T1562.001 → T1490 → T1489 → T1083 → T1486
   [Describe each step with evidence]

5. IMPACT ASSESSMENT
   - Files affected: [count from C:\LabVictimFiles]
   - Shadow copies: Deleted
   - Recovery options: [VSS gone, snapshot available]
   - Data exfiltration: [was any data exfiltrated before encryption?]

6. CONTAINMENT ACTIONS TAKEN
   - [Time]: Agent isolated via Wazuh active response
   - [Time]: Credentials rotated
   - [Time]: IOCs pushed to MISP

7. RECOVERY STEPS
   - Snapshot restored at [time]
   - Security controls re-enabled
   - Agent re-enrolled in Wazuh

8. PURPLE TEAM GAP ANALYSIS
   Paste your completed gap analysis table

9. NEW DETECTION RULES DEPLOYED
   List rule IDs 100040–100043 with descriptions

10. RECOMMENDATIONS
    - Enable shadow copy protection via VSS quota
    - Block vssadmin.exe for non-administrative users via AppLocker
    - Alert on bcdedit execution by any process
    - Implement immutable backup storage (3-2-1 rule)
    - Deploy Canary files (honey files) that trigger alerts on access
```

---

## Grading Rubric

| Section | Marks |
|---|---|
| Red Team: All 5 Atomic Red Team TTPs executed | 15 |
| Blue Team: Wazuh triage table complete | 15 |
| Attack timeline with all 6 events + timestamps | 15 |
| Memory forensics: Volatility3 output documented | 15 |
| YARA scan on memory dump | 5 |
| TheHive case opened with observables | 10 |
| Purple Team gap analysis: minimum 4 rows | 15 |
| Gap-fill detection rules deployed | 5 |
| Incident report: complete structure | 5 |
| **Total** | **100** |

Pass mark: 65
