#
# Script to extract the "hash" from WINDOWS HELLO PIN.
#
# This code is written from scratch, but is inspired by the tool "ngccryptokeysdec.py" from @tijldeneut
# (https://github.com/tijldeneut/dpapilab-ng/blob/main/ngccryptokeysdec.py) (GPL-license)
# All credit goes to him for his initial work.
#
# Tested with Python 3.9.5 and the following libraries: PyCryptodome 3.10.1 and dpapick3 0.3.1
#
# Author:
#   https://github.com/mneitsabes
#   https://github.com/Banaanhangwagen
# License: MIT
#

import argparse
import os
import re
import struct
import sys
from collections import namedtuple
from typing import Optional

try:
    from dpapick3 import blob, masterkey, registry
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3')


guid_re = re.compile('^{?([A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12})}?$')
CryptoKey = namedtuple('CryptoKey', 'description, blob_private_key_properties, blob_private_key')


class ProtectorInfo:
    """
    Protector info struct.
    """
    def __init__(self, sid: str, path: str, provider: str, guid: str):
        self.sid = sid
        self.path = path
        self.provider = provider
        self.guid = guid
        self.username = None


def parse_ngc_dir(ngcdir_path: str, software_hive_path: Optional[str]) -> {ProtectorInfo}:
    """
    Parse the NGC directory to find the PIN GUID.

    If the software hive is defined, the username is retrieved.

    :param ngcdir_path: the NGC directory
    :param software_hive_path: the software hive path
    :return:
    """
    protector_by_sids = {}

    # Regedit
    reg = registry.Regedit() if software_hive_path else None

    for d in os.listdir(ngcdir_path):
        if guid_re.match(d):
            sid_file_path = os.path.join(ngcdir_path, d, '1.dat')
            first_protectors_dirpath = os.path.join(ngcdir_path, d, 'Protectors', '1')

            if not os.path.isfile(sid_file_path):
                raise RuntimeError(f'Cannot find the SID-file (1.dat) in the subdir. "{os.path.join(ngcdir_path, d)}"')

            if not os.path.isdir(first_protectors_dirpath):
                raise RuntimeError(f'Cannot find "Protectors\\1" subdirectory in "{os.path.join(ngcdir_path, d)}". '
                                   f'Skipping\n')

            with open(sid_file_path, 'rb') as fp:
                sid = fp.read().decode('utf-16-le').rstrip('\x00')

            if sid in protector_by_sids:
                raise RuntimeError(f'The SID {sid} has already been parsed.')

            protector_by_sids[sid] = parse_protector_subdir(sid, first_protectors_dirpath)

            if reg:
                username = reg.getUsername(software_hive_path, sid)
                if username != '<Unknown>':
                    protector_by_sids[sid].username = username

        else:
            raise RuntimeError(f'"{d}" directory in "{ngcdir_path}" is not a GUID.')

    return protector_by_sids


def parse_protector_subdir(sid: str, subdir_path: str) -> ProtectorInfo:
    """
    Parse the protector subdirectory and extract the Protector info from it.

    :param sid: the corresponding SID
    :param subdir_path: the subdirectory
    :return:
    """
    provider_file_path = os.path.join(subdir_path, '1.dat')
    guid_file_path = os.path.join(subdir_path, '2.dat')

    if not os.path.isfile(provider_file_path):
        raise FileNotFoundError(f'Cannot find the provider file (1.dat) in the subdir "{subdir_path}".')

    if not os.path.isfile(guid_file_path):
        raise FileNotFoundError(f'Cannot find the GUID file (2.dat) in the subdir "{subdir_path}".')

    with open(provider_file_path, 'rb') as fp:
        provider = fp.read().decode('utf-16-le').rstrip('\x00')

    with open(guid_file_path, 'rb') as fp:
        guid = fp.read().decode('utf-16-le').rstrip('\x00')

    return ProtectorInfo(sid, subdir_path, provider, guid)


def parse_cryptokey_file(filepath: str) -> CryptoKey:
    """
    Parse a cryptokey file.

    Based on https://github.com/tijldeneut/dpapilab-ng/blob/main/ngccryptokeysdec.py#L51

    :param filepath: the file path
    :return: (the description, the fields bytes)
    """
    with open(filepath, 'rb') as fp:
        data = fp.read()

    number_of_fields = struct.unpack('<H', data[14:16])[0]
    description_len = struct.unpack('<I', data[8:12])[0]
    description = data[44:44 + description_len].decode('UTF-16LE')

    data_current_offset = 44 + description_len
    fields_data = []

    assert number_of_fields >= 3, 'At least 3 fields are required. It this file valid ?'

    for i in range(0, number_of_fields):
        field_len_offset = 16 + (4 * i)
        field_len = struct.unpack('<I', data[field_len_offset:field_len_offset+4])[0]

        fields_data.append(data[data_current_offset:data_current_offset+field_len])
        data_current_offset += field_len

    return CryptoKey(description, fields_data[1], fields_data[2])


def parse_private_key_properties(decrypted_bytes: bytes) -> dict:
    """
    Parse the decrypted private key properties of a cryptokey.

    Returns a dict where [property_name] = property_value

    Based on https://github.com/tijldeneut/dpapilab-ng/blob/main/ngccryptokeysdec.py#L67

    :param decrypted_bytes: the decrypted crypto key private key properties
    :return: the properties
    """
    properties = {}
    current_offset = 0

    while current_offset < len(decrypted_bytes):
        total_entry_size = struct.unpack('<I', decrypted_bytes[current_offset:current_offset + 4])[0]

        name_length = struct.unpack('<I', decrypted_bytes[current_offset+12:current_offset+16])[0]
        prop_length = struct.unpack('<I', decrypted_bytes[current_offset+16:current_offset+20])[0]
        name = decrypted_bytes[current_offset+20:current_offset+20+name_length].decode('UTF-16LE')
        prop = decrypted_bytes[current_offset+20+name_length:current_offset+20+name_length+prop_length]

        assert name not in properties, 'Duplicate in property name.'

        properties[name] = prop
        current_offset += total_entry_size

    return properties


def print_title(title: str):
    """
    Print the title with * underline.

    :param title: the title
    """
    print(f'[++] {title}')
    print('-' * (len(title) + 5))


if __name__ == '__main__':
    usage = 'WINHELLO2hashcat.py [--verbose]\n\t --cryptokeys <crypo keys directory>\n\t --masterkey <user masterkey ' \
            'directory>\n\t --system <system hive>\n\t --security <security hive>\n\t --pinguid <pinguid> OR --ngc <ngc directory>\n\t' \
            '[--software <software hive>]\n' \
            '[+] Or set the windows base directory with --windows\n'

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, usage=usage)
    parser.add_argument('--windows', required=False, help='Windows Offline directory')
    args, rem_args =  parser.parse_known_args()
    if (args.windows is not None):
        parser.add_argument('--cryptokeys', default = os.path.join(str(args.windows), 'ServiceProfiles','LocalService','AppData','Roaming','Microsoft','Crypto','Keys'))
        parser.add_argument('--masterkey' , default = os.path.join(args.windows, 'System32','Microsoft','Protect','S-1-5-18','User'))
        parser.add_argument('--system' , default = os.path.join(args.windows, 'System32','config','SYSTEM'))
        parser.add_argument('--security' , default = os.path.join(args.windows, 'System32','config','SECURITY'))
        parser.add_argument('--ngc' , default = os.path.join(args.windows, 'ServiceProfiles','LocalService','AppData','Local','Microsoft','Ngc'))
        parser.add_argument('--software' , default = os.path.join(args.windows, 'System32','config','SOFTWARE'))
    else:
        parser.add_argument('--cryptokeys', required=True, help='The "\\Windows\\ServiceProfiles\\LocalService\\AppData')
        parser.add_argument('--masterkey' , required=True, help='The "\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User" directory')
        parser.add_argument('--system', required=True, help='The "\\Windows\\System32\\config\\SYSTEM" hive"')
        parser.add_argument('--security', required=True, help='The "\\Windows\\System32\\config\\SECURITY" hive"\\Roaming\\''Microsoft\\Crypto\\Keys" directory')
        pin_group = parser.add_mutually_exclusive_group()
        pin_group.required = True
        pin_group.add_argument('--pinguid', help='The PIN guid')
        pin_group.add_argument('--ngc', help='The "\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\'
                                             'Microsoft\\Ngc\" directory')
        parser.add_argument('--software', help='The "\\Windows\\System32\\config\\SOFTWARE" hive"')


    parser.add_argument('--verbose', action="store_true", help='Verbose mode')
    

    args = parser.parse_args(rem_args, namespace=args)

    if not os.path.isdir(args.cryptokeys):
        sys.stderr.write('The cryptokeys directory doesn\'t exist.')
        exit(-1)

    if not os.path.isdir(args.masterkey):
        sys.stderr.write('The masterkey directory doesn\'t exist.')
        exit(-1)

    if not os.path.isfile(args.system):
        sys.stderr.write('The SYSTEM hive doesn\'t exist.')
        exit(-1)

    if not os.path.isfile(args.security):
        sys.stderr.write('The SECURITY hive doesn\'t exist.')
        exit(-1)

    if args.software and not os.path.isfile(args.software):
        sys.stderr.write('The SOFTWARE hive doesn\'t exist.')
        exit(-1)

    pinguids = []
    protector_by_sid = None
    if args.ngc:
        if not os.path.isdir(args.ngc):
            sys.stderr.write('The provided NGC directory doesn\'t exist.')
            exit(-1)

        protector_by_sid = parse_ngc_dir(args.ngc, args.software)

        if len(protector_by_sid) == 0:
            sys.stderr.write('Cannot find a PIN GUID from the NGC directory.')
            exit(-1)

        for sid in protector_by_sid.keys():
            pinguids.append(protector_by_sid[sid].guid)

            if args.verbose:
                print(f'[!] Found PIN GUID {protector_by_sid[sid].guid} for user "{protector_by_sid[sid].username}" in '
                      f'{protector_by_sid[sid].path}.')
    else:
        m_pinguid = guid_re.match(args.pinguid)
        if not m_pinguid:
            sys.stderr.write('The PIN GUID is not a valid GUID.')
            exit(-1)

        pinguids.append(('{' + m_pinguid[1].upper() + '}'))

    # Read LSA secrets for DPAPI system
    reg = registry.Regedit()
    lsa_secrets = reg.get_lsa_secrets(args.security, args.system)
    dpapi_system = lsa_secrets.get('DPAPI_SYSTEM')['CurrVal']

    # The masterkey pool
    mkp = masterkey.MasterKeyPool()
    mkp.loadDirectory(args.masterkey)
    mkp.addSystemCredential(dpapi_system)
    mkp.try_credential_hash(None, None)

    at_least_one_entry_found = False

    # Parse all crypto keys
    for file in os.listdir(args.cryptokeys):
        current_filepath = os.path.join(args.cryptokeys, file)

        if not os.path.isfile(current_filepath):
            continue

        if args.verbose:
            print(f'[+] Processing key file {current_filepath}')

        ck = parse_cryptokey_file(current_filepath)

        if args.verbose:
            print(f'Key with GUID {ck.description} found.')

        if ck.description not in pinguids:
            if args.verbose:
                print(f'Skipping key {ck.description} because it\'s not matching the targeted GUID(s).\n')
            continue

        if args.verbose:
            print('')

        private_key_properties = None
        pkp_blob = blob.DPAPIBlob(ck.blob_private_key_properties)
        mks = mkp.getMasterKeys(pkp_blob.mkguid.encode())
        for mk in mks:
            if mk.decrypted:
                pkp_blob.decrypt(mk.get_key(), entropy=b'6jnkd5J3ZdQDtrsu\x00')
                if pkp_blob.decrypted:
                    private_key_properties = parse_private_key_properties(pkp_blob.cleartext)

        if not private_key_properties:
            if args.verbose:
                print(f'Cannot decrypt the private key properties.')

            continue

        pk_blob = blob.DPAPIBlob(ck.blob_private_key)
        mks = mkp.getMasterKeys(pk_blob.mkguid.encode())
        for mk in mks:
            if mk.decrypted:
                pk_blob.decrypt(mk.get_key(), entropy=b'xT5rZW5qVVbrvpuA\x00', strongPassword='None')
                if not pk_blob.decrypted:
                    at_least_one_entry_found = True

                    masterkey = mk.get_key().hex()
                    hmac = pk_blob.hmac.hex()
                    verif_blob = pk_blob.blob.hex()
                    pin_salt = private_key_properties['NgcSoftwareKeyPbkdf2Salt'].hex()
                    pin_iterations = struct.unpack('<I', private_key_properties['NgcSoftwareKeyPbkdf2Round'])[0]
                    sign = pk_blob.sign.hex()

                    if args.verbose:
                        print_title('SYSTEM MASTER_KEY - decrypted with the LSA DPAPI secret key')
                        print(f'Masterkey : {masterkey}')
                        print('')

                        print_title('Values from DPAPI blob')
                        print(f'HashAlgo : {pk_blob.hashAlgo}')
                        # print(f'CipherAlgo : {pk_blob.cipherAlgo}')
                        print(f'HMAC : {hmac}')
                        print(f'Verif BLOB : {verif_blob}')
                        print(f'Signature BLOB : {sign}')
                        print('')

                        print_title('Values needed to convert PIN during cracking')
                        print(f'PIN salt : {pin_salt}')
                        print(f'PIN iterations : {pin_iterations}')
                        print('')

                    assert pk_blob.cipherAlgo.algnum == 0x6610, f'The CipherAlgo is not AES-256 but' \
                                                                f' {pk_blob.cipherAlgo}. Please report this.'

                    assert pk_blob.hashAlgo.algnum == 0x800e, f'The HashAlgo is not SHA512 but {pk_blob.hashAlgo}. ' \
                                                              f'Please report this.'

                    entropy = b'\x78\x54\x35\x72\x5a\x57\x35\x71\x56\x56\x62\x72\x76\x70\x75\x41\x00'.hex()
                    hashcat_format = f'$WINHELLO$*SHA512*{pin_iterations}*{pin_salt}*{sign}*{masterkey}*{hmac}*' \
                                     f'{verif_blob}*{entropy}'

                    if args.ngc:
                        current_pi = [protector_by_sid[sid] for sid in protector_by_sid
                                      if protector_by_sid[sid].guid == ck.description][0]

                        if current_pi.username:
                            print(f'{current_pi.username} :\n', end='')

                    print(hashcat_format)

                    if args.verbose:
                        print('')

    if not at_least_one_entry_found:
        sys.stderr.write('No entry found. You can try :\n')
        sys.stderr.write(' - Run with --verbose to debug\n')
        sys.stderr.write(' - Try finding the PIN GUID manually\n')
        sys.stderr.write(' - Check if a TPM was used. If so, the Crypto Provider is not supported\n')
