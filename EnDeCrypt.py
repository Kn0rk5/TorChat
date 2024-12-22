#external
import base64
import os
from cryptography.fernet import Fernet
from websockets.utils import generate_key

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Cipher import PKCS1_OAEP

from cryptography.hazmat.primitives.asymmetric import dh

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

base_encoding: str = "utf-8"


def _encode(_text) -> bytes: return _text.encode(base_encoding) if type(_text) == str else _text
def _decode(_bytes) -> str: return _bytes.decode(base_encoding) if type(_bytes) == bytes else _bytes


class Asymmetrical:
    key_len = 1024 * 4
    rsa_key_type = RsaKey

    def generateAsymmetricalKeys(self):
        _key = RSA.generate(self.key_len)
        return _key

    def import_key(self, _key):
        return RSA.importKey(_key)

    ## encrypts strings that are passed through with the variable private_key
    def encryptStringAsymmetrical(self, string: (str, bytes), public_key):
        encryptObject = PKCS1_OAEP.new(public_key)
        return encryptObject.encrypt(string.encode() if type(string) == str else string)

    def decryptStringAsymmetrical(self, string: bytes, private_key):
        decryptObject = PKCS1_OAEP.new(private_key)
        return decryptObject.decrypt(string).decode()


class Symmetrical:
    def generateSymmetricalKey(self):
        # return Fernet.generate_key()
        return base64.urlsafe_b64encode(os.urandom(32*2*2*2))

    def encryptStringSymmetrical(self, to_encrypt, key):
        f = Fernet(key)
        encrypted_string = f.encrypt(_encode(to_encrypt))
        return encrypted_string

    def decryptStringSymmetrical(self, to_decrypt: bytes, key):
        f = Fernet(key)
        decrypted_string = f.decrypt(to_decrypt)
        return decrypted_string.decode(base_encoding)


class DiffieHellman:

    def generate_dh_parameter(self):
        return dh.generate_parameters(generator=2, key_size=3072)

    def generate_private_key(self, _dh_parameter):
        return _dh_parameter.generate_private_key()

    def generate_public_key(self, _private_key):
        return _private_key.public_key()

    def calculate_shared_key(self, _private_key, _public_key):
        return _private_key.exchange(other_peer=_public_key)


class ECDH:
    key_bit_length: int = 32*2

    # RAW Keys (RAWK)
    _raw_private_key: X448PrivateKey
    _raw_public_key: X448PublicKey
    _raw_recv_public_key: X448PublicKey

    # HEX Keys (HEXK)
    hex_public_key: X448PrivateKey.public_key
    _hex_recv_public_key: bytes

    # Symmetrical shared secret keys (SSSS :))
    _hex_shared_secret_key: X448PrivateKey.exchange
    hex_derived_shared_secret_key: bytes


    def __init__(self, algorithm=hashes.SHA512(), key_bit_length=key_bit_length, salt=None, info=None):
        self.key_bit_length = key_bit_length
        self.salt = salt
        self.algorithm = algorithm
        self.info = info

    def generate_all_keys(self):
        self._generate_key_pair()
        self._generate_hex_public_key()

    def _generate_key_pair(self):
        self._raw_private_key = X448PrivateKey.generate()
        self._raw_public_key = self._raw_private_key.public_key()

    def _generate_hex_public_key(self):
        self.hex_public_key = self._raw_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def process_recv_public_key(self, recv_public_key: bytes):
        self._raw_recv_public_key = X448PublicKey.from_public_bytes(recv_public_key)

    def generate_shared_secret_key(self):
        self._exchange_key()
        self._derive_key()

    def _exchange_key(self):
        self._hex_shared_secret_key = self._raw_private_key.exchange(self._raw_recv_public_key)

    def _derive_key(self):
        self.hex_derived_shared_secret_key = HKDF(
            algorithm=self.algorithm,
            length=self.key_bit_length,
            salt=self.salt,
            info=self.info,
        ).derive(self._hex_shared_secret_key)


if __name__ == '__main__':
    dh_instance = ECDH()
    dh_instance.generate_all_keys()
    input()
