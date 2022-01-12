# WINHELLO2hashcat

## About

With this tool one can extract the "hash" from a WINDOWS HELLO PIN. This hash can be cracked with [Hashcat](https://hashcat.net), more precisely with the plugin `-m 28100`.

This tool is extensivly tested with WIN_10 21H1 and 21H2, and also with WIN_11.

Please read this post for more information: https://hashcat.net/forum/thread-10461.html


## Requirements
The Python-package `dpapick3` is needed.

## Usage
```
λ python WINHELLO2hashcat.py --help
usage: WINHELLO2hashcat.py [--verbose] --cryptokeys <crypo keys directory> --masterkey <user masterkey directory> --system <system hive> --security <security hive> [--pinguid <pinguid>|--ngc <ngc directory>] [--software <software hive>]

optional arguments:
  -h, --help            show this help message and exit
  --verbose             Verbose mode
  --cryptokeys CRYPTOKEYS
                        The "\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys" directory
  --masterkey MASTERKEY
                        The "\Windows\System32\Microsoft\Protect\S-1-5-18\User" directory
  --system SYSTEM       The "\Windows\System32\config\SYSTEM" hive"
  --security SECURITY   The "\Windows\System32\config\SECURITY" hive"
  --pinguid PINGUID     The PIN guid
  --ngc NGC             The "\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" directory
  --software SOFTWARE   The "\Windows\System32\config\SOFTWARE" hive"
  --windows PATH        The windows offline directory and autodetect the system, masterkey, cryptokeys, ngc and software arguments
```
- CRYPTOKEYS-folder, MASTERKEY-folder, SYSTEM and SECURITY hives are mandatory
- NGC-folder or PIN_GUID is mandatory. Be aware that on a live (mounted) system, acces to this folder requires SYSTEM privilege.
- SOFTWARE hive is optional; only needed to print the username

## Remarks
- On systems with a TPM (hardware or firmware versions), this script will not work because the needed keys are protected.
- Screenshot of login screen where PIN is asked. Notice that Windows does an auto-enter after the correct number of digits is entered.  
![image1](https://user-images.githubusercontent.com/25983612/141965671-13faf0e1-1fca-4dad-9e6c-50ac6f8bf90d.png)

- Screenshot of login where PIN is asked, but this time there is a letter/symbol added. Notice that there is no auto-enter anymore, but an arrow is added to the field.

![image2](https://user-images.githubusercontent.com/25983612/141985995-0b7ff0bd-16d9-4d6a-9440-cbc53acda340.png)

- This script is provided as-is. Please report any issues.
- Happy cracking!
