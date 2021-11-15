# WINHELLO2hashcat

## About

With this tool one can extract the "hash" from a WINDOWS HELLO PIN. This hash can be cracked with [Hashcat](https://hashcat.net), more precisely with the plugin `-m 28100`.

This tool is extensivly tested with WIN_10 21H1 and 21H2, and also with WIN_11.

Please read this post for more information: 


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
```
- CRYPTOKEYS-folder, MASTERKEY-folder, SYSTEM and SECURITY hives are mandatory
- NGC-folder or PIN_GUID is mandatory. Be aware that on a live (mounted) system, acces to this folder requires SYSTEM privilege.
- SOFTWARE hive is optional; only needed to print the username

## Remarks
- On systems with a TPM, this script will not work.
- This script is provided as-is. Please report any issues.
- Happy cracking!
