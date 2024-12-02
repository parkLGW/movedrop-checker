from aptos_sdk.ed25519 import PrivateKey
from aptos_sdk.account import Account


class Aptos:
    def __init__(self, private_key):
        self.private_key = private_key

    def _convert_signing_message(self, message):
        if isinstance(message, str):
            try:
                bytes.fromhex(message)
                return message
            except ValueError:
                return message.encode('utf-8')
        return message

    @staticmethod
    def create_random_wallet():
        return Aptos(Account.generate().private_key.hex())

    def sign_message(self, message: bytes):
        pk = PrivateKey.from_str(self.private_key)
        return pk.sign(message).__str__()

    def get_private_key(self):
        return self.private_key

    def get_pubkey(self):
        pk = PrivateKey.from_str(self.private_key)
        return pk.public_key()

    def get_address(self):
        account = Account.load_key(self.private_key)
        return account.address().__str__()
