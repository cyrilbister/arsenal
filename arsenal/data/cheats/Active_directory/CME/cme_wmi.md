# cme (WMI)

% cme, crackmapexec, Active Directory, nxc, netexec, wmi

## Enumerate WMI reachable hosts
#assessment/AD #attack_type/Enumeration #port/135 #protocol/wmi #access/Anonymous 

Enumerate network hosts that can be reached via WMI.

```bash
cme wmi <ip>
```

## Domain auth
#assessment/AD #attack_type/Authentication #port/135 #protocol/wmi #access/Domain_user 

Authenticate via a domain account on the remote target.

```bash
cme wmi <ip> -u <user> -p <password> -d <domain>
```

## Domain auth with hash
#assessment/AD #attack_type/Authentication #port/135 #protocol/wmi #access/Domain_user 

```bash
cme wmi <ip> -u <user> -H <hash> -d <domain>
```

## Local auth
#assessment/AD #attack_type/Authentication #port/135 #protocol/wmi #access/Local_user

Authenticate via a local account on the remote target.

```bash
cme wmi <ip> -u <user> -p <password> --local-auth
```

## Local auth with hash
#assessment/AD #attack_type/Authentication #port/135 #protocol/wmi #access/Local_user

Authenticate via a local account using the hash on the remote target.

```bash
cme wmi <ip> -u <user> -H <hash> --local-auth
```

## Kerberos auth
#assessment/AD #attack_type/Authentication #port/135 #protocol/wmi #access/Domain_user 

Authenticate via Kerberos on the remote target.

```bash
cme wmi <ip> -u <user> -p <password> -k
```

## Kerberos TGT auth
#assessment/AD #attack_type/Authentication #port/135 #protocol/wmi #access/Domain_user 

Authenticate via a Kerberos TGT on the remote target.

Previously import ticket : 
export KRB5CCNAME=ticket.ccache

```bash
cme wmi <ip> -u <user> -k --use-kcache
```

## Password spray (username=password)
#assessment/AD #attack_type/Bruteforce #port/135 #protocol/wmi #access/Anonymous 

Password spray to find accounts with weak passwords.

```bash
cme wmi <ip> -u <users.list> -p <users.list> --no-bruteforce --continue-on-success
```

## Execute remote commands (CMD)
#assessment/AD #attack_type/Command_Execution #port/135 #protocol/wmi #access/Domain_user 

Execute remote commands through Windows CMD.

```bash
cme wmi <ip> -u <user> -p <password> -x <command>
```

## Execute WMI query
#assessment/AD #attack_type/Command_Execution #port/135 #protocol/wmi #access/Domain_user 

Execute remote WMI queires.

```bash
cme wmi <ip> -u <user> -p <password> --wmi <query>
```

= ip: 192.168.1.0/24
= dc-ip: $DC_IP
= user: $USER
= password: $PASSWORD
= domain: $DOMAIN
