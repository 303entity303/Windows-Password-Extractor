import colorama

colorama.init()

import argparse
import json
from binascii import unhexlify
from pathlib import Path

from Cryptodome.Cipher import DES, AES
from Cryptodome.Hash import MD4

# noinspection PyPackageRequirements
from Registry import Registry

from utils import ft2dt

import sys


# Entry Structure (ES)
class ES:
    NAME = 0
    TYPE = 1
    OFFSET = 2
    LENGTH = 3


class Vector:
    def __init__(self, data):
        self.data = data

    def __repr__(self):
        return '(' + ', '.join(map(str, list(self.data))) + ')'

    def __len__(self):
        return len(self.data)

    def __getitem__(self, key):
        return self.data[key]


# SAM Hash
class SAMHash:
    def __init__(self, data):
        self.__entries = [
            ('PEKid', 'i', 0x00, 0x02),
            ('Version', 'i', 0x02, 0x02),
            ('DataOffset', 'i', 0x04, 0x04),
            ('IV', 'v', 0x08, 0x10),
            ('HashData', 'b', 0x18, 0x00),
        ]

        self.data = data

        for name, _, _, _ in self.__entries:
            setattr(self, name.lower(), None)

        self.parse()

    def select(self, entry):
        return self.data[entry[ES.OFFSET]:(entry[ES.OFFSET] + entry[ES.LENGTH]) if entry[ES.LENGTH] else None]

    def parse(self):
        for entry in self.__entries:
            value = None

            match entry[ES.TYPE]:
                case 'i':
                    value = int.from_bytes(
                        bytes(self.select(entry)),
                        'little'
                    )
                case 'b':
                    value = bytes(self.select(entry))
                case 'v':
                    value = Vector(self.select(entry))

            setattr(self, entry[ES.NAME].lower(), value)

    def __repr__(self):
        return (
            f'🔒 SAMHash [{len(self)} bytes] ↓ ↓\n'
        ) + '\n'.join(
            [
                '\t' +
                f'{'✔️ ' if getattr(self, entry[ES.NAME].lower()) is not None else '❌ '}' +
                f'{entry[ES.NAME] + ':' : <30}' +
                (str(getattr(self, entry[ES.NAME].lower())))
                for entry in self.__entries
            ]
        )

    def __len__(self):
        return len(self.data)


# AES Data
class AESData:
    def __init__(self, data):
        self.__entries = [
            ('Version', 'i', 0x00, 0x04),
            ('Length', 'i', 0x04, 0x04),
            ('ChecksumLength', 'i', 0x08, 0x04),
            ('DataLength', 'i', 0x0C, 0x04),
            ('IV', 'v', 0x10, 0x10),
            ('Data', 'b', 0x20, 0x00),
        ]

        self.__data = data

        for name, _, _, _ in self.__entries:
            setattr(self, name.lower(), None)

        self.parse()

    def select(self, entry):
        return self.__data[entry[ES.OFFSET]:(entry[ES.OFFSET] + entry[ES.LENGTH]) if entry[ES.LENGTH] else None]

    def parse(self):
        for entry in self.__entries:
            value = None

            match entry[ES.TYPE]:
                case 'i':
                    value = int.from_bytes(
                        bytes(self.select(entry)),
                        'little'
                    )
                case 'b':
                    value = bytes(self.select(entry))
                case 'v':
                    value = Vector(self.select(entry))

            setattr(self, entry[ES.NAME].lower(), value)


    def __repr__(self):
        values = (
            f'🔒 AESData [{len(self)} bytes] ↓ ↓\n'
        )

        for entry in self.__entries:
            values += (
                '\t' +
                f'{'✔️ ' if getattr(self, entry[ES.NAME].lower()) is not None else '❌ '}' +
                f'{entry[ES.NAME] + ':' : <30}' +
                (str(getattr(self, entry[ES.NAME].lower()))) +
               '\n'
            )

        return values

    def __len__(self):
        return len(self.__data)

# F (domain)
class Fd:
    def __init__(self, data):
        self.__entries = [
            ('Version', 'h', 0x00, 0x04),
            ('AliasCount', 'i', 0x04, 0x04),
            ('CreationTime', 't', 0x08, 0x08),
            ('DomainModifiedCount', 'i', 0x10, 0x08),
            ('MaxPasswordAge', 'dt', 0x18, 0x08),
            ('MinPasswordAge', 'dt', 0x20, 0x08),
            ('ForceLogoff', 'dt', 0x28, 0x08),
            ('LockoutDuration', 'dt', 0x30, 0x08),
            ('LockoutObservationWindow', 'dt', 0x38, 0x08),
            ('ModifiedCountAtLastPromotion', 'i', 0x40, 0x08),
            ('NextRID', 'i', 0x48, 0x04),
            ('PasswordProperties', 'lb', 0x4C, 0x04),
            ('MinPasswordLength', 'i', 0x50, 0x02),
            ('PasswordHistoryLength', 'i', 0x52, 0x02),
            ('LockoutThreshold', 'i', 0x54, 0x02),
            ('F1', 'b', 0x56, 0x02),
            ('DomainServerState', 'i', 0x58, 0x04),
            ('DomainServerRole', 'i', 0x5C, 0x02),
            ('UASCompatibilityRequired', 'i', 0x5E, 0x02),
            ('F2', 'lb', 0x60, 0x08),
            ('Key', 'k', 0x68, 0x00),
        ]

        self.__f = data

        for name, _, _, _ in self.__entries:
            setattr(self, name.lower(), None)

        self.parse()

    def select(self, entry):
        return self.__f[entry[ES.OFFSET]:(entry[ES.OFFSET] + entry[ES.LENGTH]) if entry[ES.LENGTH] else None]

    def parse(self):
        for entry in self.__entries:
            value = None

            match entry[ES.TYPE]:
                case 'h':
                    ver = int.from_bytes(bytes(self.select(entry)), 'little').to_bytes(length=4)
                    value = f'{int.from_bytes(ver[:2])}.{int.from_bytes(ver[2:])}'
                case 't':
                    stamp = int.from_bytes(
                        bytes(self.select(entry)),
                        'little'
                    )
                    value = ft2dt(stamp)
                case 'dt':
                    binary_stamp = bytes(self.select(entry))

                    low = int.from_bytes(binary_stamp[:4], 'little', signed=False)
                    high = int.from_bytes(binary_stamp[4:], 'little', signed=True)

                    stamp = (high << 32) + low

                    value = f'Δ{abs(stamp) // 10 ** 7} seconds'
                case 's':
                    value = bytes(self.select(entry)).decode('utf-16')
                case 'b':
                    value = '0x' + bytes(self.select(entry)).hex()
                case 'lb':
                    value = '0x' + bytes(self.select(entry))[::-1].hex()
                case 'i':
                    value = int.from_bytes(
                        bytes(self.select(entry)),
                        'little'
                    )
                case 'k':
                    value = AESData(self.select(entry))

            setattr(self, entry[ES.NAME].lower(), value)

    def __repr__(self):
        values = (
            f'Fd [{len(self)} bytes]:\n'
        )

        for entry in self.__entries:
            values += (
                f'{'✔️ ' if getattr(self, entry[ES.NAME].lower()) is not None else '❌ '}' +
                f'{entry[ES.NAME] + ':' : <30}' +
                (str(getattr(self, entry[ES.NAME].lower()))) +
               '\n'
            )

        return values

    def __len__(self):
        return len(self.__f)


# V Entry Structure (VES)
class VES:
    NAME = 0
    TYPE = 1


# V Header Structure (VHS)
class VHS:
    OFFSET = 0
    LENGTH = 1
    EXTRA = 2
    SERVICE_LENGTH = 3


# V
class V:
    def __init__(self, data):
        self.__base = 0xCC
        self.__entries = [
            ('Version', 'h'),
            ('UserName', 's'),
            ('FullName', 's'),
            ('Description', 's'),
            ('UserDescription', 's'),
            ('V1', 'u'),
            ('HomeDirectory', 's'),
            ('HomeDirectoryConnect', 's'),
            ('ScriptPath', 's'),
            ('ProfilePath', 's'),
            ('Workstations', 's'),
            ('HoursAllowed', 'i'),
            ('V3', 'b'),
            ('LMHash', 'k'),
            ('NTHash', 'k'),
            ('V4', 'b'),
            ('V5', 'b'),
        ]

        self.__length = len(data)

        for name, _ in self.__entries:
            setattr(self, name.lower(), None)

        self.parse(data)

    def parse(self, data):
        for i, entry in enumerate(self.__entries):
            setattr(self, entry[0].lower(), VEntry(data, self.__base, i * 0x0C, *entry))

    def __repr__(self):
        return (
            (
                f'\nV [{len(self)} bytes]:\n') +
                '\n'.join(
                    [
                        str(
                            getattr(self, entry[0].lower())
                        )
                        for entry in self.__entries
                    ]
                )
        )

    def __len__(self):
        return self.__length


# V Entry
class VEntry:
    def __init__(self, data, base, offset, name, t):
        self.__base = base

        self.name = name
        self.service = []
        self.type = t

        # Calculate data offset, length, and the extra field
        for i in range(VHS.SERVICE_LENGTH):
            self.service.append(
                int.from_bytes(bytes(data[offset + (i * 4):offset + (i + 1) * 4]), byteorder='little') +
                (self.__base if i == VHS.OFFSET else 0)
            )

        self.data = self.parse(data)

    def select(self, v):
        return v[
                   self.service[VHS.OFFSET]:
                   self.service[VHS.OFFSET] + self.service[VHS.LENGTH]
               ]

    def parse(self, v):
        if self.service[VHS.LENGTH] == 0:
            return None

        match self.type:
            case 'h':
                ver = self.service[VHS.EXTRA].to_bytes(length=4)
                return f'{int.from_bytes(ver[:2])}.{int.from_bytes(ver[2:])}'
            case 's':
                return bytes(self.select(v)).decode('utf-16')
            case 'b':
                return '0x' + bytes(self.select(v)).hex()
            case 'i':
                return int.from_bytes(
                    bytes(self.select(v)),
                    'little'
                )
            case 'k':
                return SAMHash(self.select(v))
            case _:
                return None

    def __repr__(self):
        if self.type != 'h':
            service_string = f' @ V[0x{self.__base:04X} + 0x{self.service[VHS.OFFSET]:04X}]: |{self.service[VHS.LENGTH]}| / 0x{self.service[VHS.EXTRA]:04X}'
        else:
            service_string = f' (first entry: 0x{self.__base:02X} + 0x{self.service[1]:02X} = 0x{self.__base + self.service[1]:04X})'

        return (
            f'{'✔️ ' if self.data else '❌ '}' +
            f'{self.name + ':' : <30}' +
            (f'{self.data or self.service}') +
            (service_string if self.data else '')
        )

    def __len__(self):
        return self.service[VHS.LENGTH]


# ResetData
class ResetData:
    def __init__(self, data):
        self.version = 0
        self.questions = []

        self.parse(data)

    def parse(self, data):
        data = json.loads(bytes(data).decode('utf-16-le'))

        self.version = data['version']

        for question in data['questions']:
            self.questions.append(
                {
                    'question': question['question'],
                    'answer': question['answer']
                }
            )

    def __repr__(self):
        return '\n'.join(
            f'❓ {question['question']}\n💡 {question['answer']}'
            for question in self.questions
        )

    def __len__(self):
        return len(json.dumps(self.questions).encode('utf-16-le'))


class LMUser:
    def __init__(self, rid, data):
        self.rid = rid
        self.k = []
        self.v = V(data['V'])
        self.reset_data = ResetData(data['ResetData']) if 'ResetData' in data else None
        self.reset_force = not not int.from_bytes(bytes(data['ForcePasswordReset']), 'little') if 'ForcePasswordReset' in data else False
        self.hint = bytes(data['UserPasswordHint']).decode('utf-16-le') if 'UserPasswordHint' in data else None
        self.decrypted_hashes = None
        self.encrypted_hashes = None

        self.compute_keys()

    def compute_keys(self):
        # RID is a 32-bit LE integer
        rid = self.rid.to_bytes(32, 'little')

        # K1 = R[0] || R[1] || R[2] || R[3] || R[0] || R[1] || R[2]
        # K2 = R[3] || R[0] || R[1] || R[2] || R[3] || R[0] || R[1]
        self.k += [
            [rid[0], rid[1], rid[2], rid[3], rid[0], rid[1], rid[2]],
            [rid[3], rid[0], rid[1], rid[2], rid[3], rid[0], rid[1]]
        ]

        for i, key in enumerate(self.k):
            key = [
                key[0] >> 1,
                (key[0] & 0x01) << 6 | key[1] >> 2,
                (key[1] & 0x03) << 5 | key[2] >> 3,
                (key[2] & 0x07) << 4 | key[3] >> 4,
                (key[3] & 0x0F) << 3 | key[4] >> 5,
                (key[4] & 0x1F) << 2 | key[5] >> 6,
                (key[5] & 0x3F) << 1 | key[6] >> 7,
                key[6] & 0x7F
            ]

            for j in range(8):
                key[j] <<= 1
                key[j] &= 0xFE

            self.k[i] = bytes(key)

    def __repr__(self):
        nt_hash = self.decrypted_hashes[0].hex() if self.decrypted_hashes[0] else 'None'
        lm_hash = self.decrypted_hashes[1].hex() if self.decrypted_hashes[1] else 'None'

        return (
            'Deobfuscation keys:\n' +
            '\n'.join(
                f'K{i + 1}: 0x{key.hex()}'
                for i, key in enumerate(self.k)
            ) +
            f'\nLM hash: {lm_hash}\n' +
            f'NT hash: {nt_hash}\n' +
            f'ResetData: {self.reset_data if self.reset_data else "None"}\n'
        )


class LMDomain:
    def __init__(self, reg_file=None, sam_hive_path=None, jd=None, skew1=None, gbg=None, data=None, pw=None):
        self.users = []
        self.lsa_key = [0 for _ in range(16)]
        self.boot_key = None
        self.fd = None

        if sam_hive_path:
            self.load_from_sam_hive(sam_hive_path)
        elif reg_file:
            self.load_from_reg_dump(reg_file)
        else:
            raise ValueError('Either reg_file or sam_hive_file must be provided.')

        self.acquire_boot_key(jd, skew1, gbg, data)
        self.decrypt_hash()

        if pw is not None:
            self.encrypt_hash(pw)

    def load_from_sam_hive(self, hive_file):
        sam = Registry.Registry(hive_file)

        # Read the domain data
        domain_key = sam.open('SAM\\Domains\\Account')

        try:
            f_value = domain_key.value('F').value()
        except Registry.RegistryValueNotFoundException:
            print('F value not found in SAM\\Domains\\Account')
            return

        # Store domain data
        self.fd = Fd(f_value)

        # Now read user accounts
        users_key = sam.open('SAM\\Domains\\Account\\Users')

        for user_subkey in users_key.subkeys():
            rid_str = user_subkey.name()
            try:
                rid = int(rid_str, 16)
            except ValueError:
                continue  # Skip any subkeys that are not valid RIDs

            data = {}

            try:
                v_value = user_subkey.value('V').value()
                data['V'] = v_value
            except Registry.RegistryValueNotFoundException:
                continue  # Skip users without 'V' value

            try:
                f_value = user_subkey.value('F').value()
                data['F'] = f_value
            except Registry.RegistryValueNotFoundException:
                continue  # Skip users without 'F' value

            try:
                hint_value = user_subkey.value('UserPasswordHint').value()
                data['UserPasswordHint'] = hint_value
            except Registry.RegistryValueNotFoundException:
                pass  # 'UserPasswordHint' is optional

            try:
                reset_data_value = user_subkey.value('ResetData').value()
                data['ResetData'] = reset_data_value
            except Registry.RegistryValueNotFoundException:
                pass  # 'ResetData' is optional

            try:
                force_password_reset_value = user_subkey.value('ForcePasswordReset').value()
                data['ForcePasswordReset'] = force_password_reset_value
            except Registry.RegistryValueNotFoundException:
                pass  # 'ForcePasswordReset' is optional

            # Create LMUser instance
            user = LMUser(rid, data)
            self.users.append(user)

    def load_from_reg_dump(self, file):
        with open(file, 'r', encoding='utf-16') as f:
            data = {}

            read_user = False
            read_domain = False
            next_key = None
            radix = 16
            rid = 0

            lines = f.readlines()

            for i, line in enumerate(lines):
                line = line.strip()

                if len(line) == 0:
                    if read_user:
                        self.users.append(LMUser(rid, data))
                        data.clear()
                        read_user = False

                    if read_domain:
                        self.fd = Fd(data['F'])
                        data.clear()
                        read_domain = False

                    next_key = None

                    continue

                if line.startswith('[') and line.endswith(']'):
                    current_key = line[1:-1]

                    if current_key == 'HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account':
                        read_domain = True

                    elif current_key.find('HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users') != -1:
                        user_key = line[1:-1].split('\\')

                        try:
                            rid = int(user_key[-1], 16)
                        except ValueError:
                            continue
                        else:
                            read_user = True

                    continue

                if read_user or read_domain:
                    if len(line) == 0:
                        continue

                    if not next_key:
                        kv = line.split('=')

                        if len(kv) != 2:
                            print(f'Potentially corrupt data on line {i + 1}! Skipping...')
                            continue

                        key = kv[0][1:-1]
                        value = kv[1]

                        if value.find(':') != -1:
                            chunks = value.split(':')

                            match chunks[0]:
                                case 'dword':
                                    radix = 10
                                case 'hex':
                                    radix = 16
                                case _:
                                    print(f'Unknown data type: {chunks[0]}! Skipping...')
                                    continue

                            value = chunks[1]

                        if value[-1] == '\\':
                            next_key = key
                            value = value[:-1]

                            if value[-1] == ',':
                                value = value[:-1]

                        current = [int(byte, radix) for byte in value.split(',')]

                        if key not in data:
                            data[key] = current
                        else:
                            data[key] += current

                    else:
                        trailing = False

                        if line[-1] == '\\':
                            line = line[:-1]
                            trailing = True

                        if line[-1] == ',':
                            line = line[:-1]

                        data[next_key] += [int(byte, radix) for byte in line.split(',')]

                        if not trailing:
                            next_key = None

    @staticmethod
    def is_valid_arg(arg):
        if len(arg) != 8:
            return False

        try:
            int(arg, 16)
        except ValueError:
            return False

        return True

    def hash_nt(self, password):
        """ Compute the NTLM hash of a password. """

        # Nice and simple, just hash the UTF-16-LE encoded password with MD4.
        # MD4(UTF-16-LE(password))
        encoded_password = password.encode('utf-16-le')
        md4 = MD4.new(encoded_password).digest()

        return md4

    def hash_lm(self, password):
        """ Compute the Lan Manager (LM) hash of a password. """

        # https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview#passwords-stored-as-owf
        # 1. The password is padded with NULL bytes to exactly 14 characters. If the password is longer than 14 characters, it is replaced with 14 NULL bytes for the remaining operations.
        # 2. The password is converted to all uppercase.
        # 3. The password is split into two 7-byte (56-bit) keys.
        # 4. Each key is used to encrypt a fixed string.
        # 5. The two results from step 4 are concatenated and stored as the LM hash.
        fixed_string = b'KGS!@#$%'
        hash_length = 14

        if len(password) > hash_length:
            password = password[:hash_length]

        password = password.upper().ljust(hash_length, '\x00').encode('utf-8')

        # DES parity bit calculation twiddle (64-bit value)
        # http://graphics.stanford.edu/~seander/bithacks.html#ParityParallel
        def parity(v):
            return (v << 1) | (0x9669 >> ((v ^ (v >> 4)) & 0x0F)) & 0x01 if not v & ~0x7F else 0

        k = [password[:hash_length // 2], password[hash_length // 2:]]

        # The part Microsoft doesn't disclose: DES encryption is used, we have to expand the keys
        # to 8 bytes and calculate a parity bit for each byte
        k = [
            b''.join(
                (
                    parity(int.from_bytes(key, 'big') >> (0x07 * (shift - 1)) & 0x7F)
                ).to_bytes() for shift in range(8, 0, -1)
            ) for key in k
        ]

        # The «fixed string» is KGS!@#$%, and it's encrypted with DES using the keys
        h = [
            DES.new(key, mode=DES.MODE_ECB).encrypt(fixed_string) for key in k
        ]

        return b''.join(h)

    def acquire_boot_key(self, jd, skew1, gbg, data):
        print("acquiring boot key")
        keys = [
            ('JD', jd),
            ('Skew1', skew1),
            ('GBG', gbg),
            ('Data', data)
        ]

        lsa_key = b''

        for key, value in keys:
            while value is None or not self.is_valid_arg(value):
                value = input()

            lsa_key += value.encode('utf-8')

        lsa_key = unhexlify(lsa_key)

        for index, scrambled in enumerate(
            [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
        ):
            self.lsa_key[index] = lsa_key[scrambled]

        print(f'LSA key: 0x{bytes(self.lsa_key).hex()}')

        self.boot_key = self.decrypt_aes(
            bytes(self.lsa_key),
            self.fd.key.data[:self.fd.key.datalength],
            bytes(self.fd.key.iv.data)
        )[:16]

        print(f'Boot Key: 0x{self.boot_key.hex()}')
        if args.LBO:
            print("exiting")
            sys.exit()
    def decrypt_hash(self):
        for user in self.users:
            d = [DES.new(key, mode=DES.MODE_ECB) for key in user.k]
            h = [user.v.nthash, user.v.lmhash]

            dec = [
                self.decrypt_aes(
                    self.boot_key,
                    hash.data.hashdata,
                    bytes(hash.data.iv.data)
                )[:16] for hash in h
            ]

            # NTHash is split into 2 8-byte chunks and passed through DES ← (K1, K2)
            user.decrypted_hashes = [
                d[0].decrypt(decr[:8]) + d[1].decrypt(decr[8:]) for decr in dec
            ]

    def encrypt_hash(self, pw):
        for user in self.users:
            user.v.nthash.data.hashdata = self.hash_nt(pw)
            user.v.lmhash.data.hashdata = self.hash_lm(pw)

            d = [DES.new(key, mode=DES.MODE_ECB) for key in user.k]
            h = [user.v.nthash, user.v.lmhash]

            enc = [
                self.encrypt_aes(
                    self.boot_key,
                    hash.data.hashdata,
                    bytes(hash.data.iv.data)
                ) for hash in h
            ]

            # NTHash is split into 2 8-byte chunks and passed through DES ← (K1, K2)
            user.encrypted_hashes = [
                d[0].encrypt(encr[:8]) + d[1].encrypt(encr[8:]) for encr in enc
            ]

    def decrypt_aes(self, key, value, iv=None):
        result = b''

        # If no IV is provided, use an empty vector
        # IV = (0, 0, ..., 0)
        if iv is None:
            iv = b'\x00' * 16

        aes256 = AES.new(key, AES.MODE_CBC, iv)

        for index in range(0, len(value), 16):
            cipher = value[index:index + 16]

            # Pad buffer to 16 bytes if it's less than a full block
            if len(cipher) < 16:
                cipher += b'\x00' * (16 - len(cipher))

            result += aes256.decrypt(cipher)

        return result

    def encrypt_aes(self, key, value, iv=None):
        result = b''

        # If no IV is provided, use an empty vector
        # IV = (0, 0, ..., 0)
        if iv is None:
            iv = b'\x00' * 16

        aes256 = AES.new(key, AES.MODE_CBC, iv)

        for index in range(0, len(value), 16):
            cipher = value[index:index + 16]

            # Pad buffer to 16 bytes if it's less than a full block
            if len(cipher) < 16:
                cipher += b'\x00' * (16 - len(cipher))

            result += aes256.encrypt(cipher)

        return result

    def __repr__(self):
        # empty_nt_hash = bytes.fromhex('31d6cfe0d16ae931b73c59d7e0c089c0')
        # empty_lm_hash = bytes.fromhex('aad3b435b51404eeaad3b435b51404ee')
        output = []

        for user in self.users:
            nt_hash, lm_hash = user.decrypted_hashes

            columns = {
                'User': user.v.username.data,
                'K1': f'0x{user.k[0].hex()}',
                'K2': f'0x{user.k[1].hex()}',
                'LM hash': lm_hash.hex(),
                'Password Hash(NT hash)': nt_hash.hex(),
                'Security Questions (ResetData)': f"\n{self._format_reset_data(user.reset_data)}",
            }

            output.append('\n'.join(
                f'{name}: {value}'
                for name, value in columns.items()
            ))

        return '\n\n'.join(output)

    @staticmethod
    def _format_reset_data(reset_data):
        return str(reset_data) if reset_data else 'None'


def get_class_names(system_hive: Path) -> dict[str, str]:
    with open(system_hive, 'rb') as f:
        system = Registry.Registry(f)

    lsa = system.open('ControlSet001\\Control\\Lsa')

    # noinspection PyProtectedMember
    return {
        'jd': lsa.subkey('JD')._nkrecord.classname(),
        'skew1': lsa.subkey('Skew1')._nkrecord.classname(),
        'gbg': lsa.subkey('GBG')._nkrecord.classname(),
        'data': lsa.subkey('Data')._nkrecord.classname()
    }

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decrypt NT/LM password hashes using boot key components.')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--reg', help='Path to the HKLM\\SAM registry export file (non-binary .reg format)')
    group.add_argument('--hive',
                       help='Path to a directory containing SAM and SYSTEM hives (e.g. %%systemroot%%\\System32\\config), must not be in use')

    parser.add_argument('--jd', help='JD class name (4 bytes)')
    parser.add_argument('--skew1', help='Skew1 class name (4 bytes)')
    parser.add_argument('--gbg', help='GBG class name (4 bytes)')
    parser.add_argument('--data', help='Data key class name (4 bytes)')
    parser.add_argument('--pw', help='Custom password to hash & encrypt for every user found')
    parser.add_argument('--LBO', help='Extracts LSA key and BOOT key only',action="store_true")

    args = parser.parse_args()
    print(args.LBO)
    if args.reg:
        domain = LMDomain(reg_file=args.reg, jd=args.jd, skew1=args.skew1, gbg=args.gbg, data=args.data, pw=args.pw)
    elif args.hive:
        config_path = Path(args.hive)
        domain = LMDomain(sam_hive_path=config_path / 'SAM', pw=args.pw, **get_class_names(config_path / 'SYSTEM'))
    else:
        raise ValueError('Either --reg or --hive must be provided.')

    output = domain
    print(type(domain))
    print(output)