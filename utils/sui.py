import base64
import bip_utils
import binascii
import hashlib
from nacl.signing import SigningKey

SUI_DERIVATION_PATH = "m/44'/784'/0'/0'/0'"


class SignatureScheme:
    ED25519 = 'ED25519'
    Secp256k1 = 'Secp256k1'


class Sui:
    def __init__(self, mnemonic='', private_key=''):
        self.mnemonic = mnemonic
        self.private_key = private_key
        self.private_key_bytes = bytes()
        self.public_key_bytes = bytes()
        if self.mnemonic != '':
            self.from_mnemonic()
        elif self.private_key != '':
            self.from_private_key()

    def from_mnemonic(self):
        bip39_seed = bip_utils.Bip39SeedGenerator(self.mnemonic).Generate()
        bip32_ctx = bip_utils.Bip32Slip10Ed25519.FromSeed(bip39_seed)
        bip32_der_ctx = bip32_ctx.DerivePath(SUI_DERIVATION_PATH)
        self.private_key_bytes = bip32_der_ctx.PrivateKey().Raw().ToBytes()
        self.public_key_bytes = bip32_der_ctx.PublicKey().RawCompressed().ToBytes()

    def from_private_key(self):
        if self.private_key[:2] == '0x':
            self.private_key = self.private_key[2:]
        self.private_key_bytes = binascii.unhexlify(self.private_key)
        bip32_ctx = bip_utils.Bip32Slip10Ed25519.FromPrivateKey(self.private_key_bytes)
        self.public_key_bytes = bip32_ctx.PublicKey().RawCompressed().ToBytes()

    @staticmethod
    def create_random_wallet():
        return Sui(
            mnemonic=bip_utils.Bip39MnemonicGenerator().FromWordsNumber(bip_utils.Bip39WordsNum.WORDS_NUM_24).ToStr())

    def get_pubkey(self):
        return self.public_key_bytes.hex()

    def get_pubkey_bytes(self):
        return self.public_key_bytes

    def get_private_key(self):
        return '0x' + self.private_key_bytes.hex()

    def get_private_key_bytes(self):
        return self.private_key_bytes

    def get_address(self):
        address: str = (
                "0x" + hashlib.blake2b(self.public_key_bytes, digest_size=32).digest().hex()[:]
        )
        return address

    def sign_data(self, data: bytes) -> str:
        intent = bytearray()
        intent.extend([0, 0, 0])
        intent = intent + data
        hash_data = hashlib.blake2b(intent, digest_size=32).digest()

        result = SigningKey(self.private_key_bytes).sign(hash_data)[:64]
        temp = bytearray()
        temp.append(0)
        temp.extend(result)
        temp.extend(self.public_key_bytes[1:])
        return base64.b64encode(temp).decode()

    def sign_message(self, msg):
        msg_bytearray = bytearray(msg.encode("utf-8"))
        intent = bytearray()
        intent.extend([3, 0, 0, len(msg_bytearray)])
        intent = intent + msg_bytearray
        hash_data = hashlib.blake2b(intent, digest_size=32).digest()

        result = SigningKey(self.private_key_bytes).sign(hash_data)[:64]
        temp = bytearray()
        temp.append(0)
        temp.extend(result)
        temp.extend(self.public_key_bytes[1:])
        return base64.b64encode(temp).decode()
