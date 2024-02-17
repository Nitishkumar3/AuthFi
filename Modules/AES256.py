# pip install pycryptodome
# AES 256 GCM

import secrets
import string
from hashlib import blake2b, sha256, sha512
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

def GenerateRandomString(Length=16):
    Characters = string.ascii_letters + string.digits
    Random = ''.join(secrets.choice(Characters) for _ in range(Length))
    return Random

def DeriveKey(UserID, DateCreated, Parameter, KeyLength=32):
    UserIDHash = sha512(UserID.encode('utf-8')).hexdigest()
    DateCreatedHash = sha256(DateCreated.encode('utf-8')).hexdigest()
    ParameterHash = sha256(Parameter.encode('utf-8')).hexdigest()
    Hash = blake2b(f"{UserIDHash}{DateCreatedHash}{ParameterHash}".encode('utf-8')).hexdigest()
    Key = PBKDF2(Hash, b'', dkLen=KeyLength, count=10000)
    return Key

def Encrypt(Plaintext, Key):
    IV = get_random_bytes(AES.block_size)
    Cipher = AES.new(Key, AES.MODE_GCM, nonce=IV)
    EncryptedText, Tag = Cipher.encrypt_and_digest(Plaintext.encode('utf-8'))
    return IV + EncryptedText + Tag

def Decrypt(EncryptedText, Key):
    IV = EncryptedText[:AES.block_size]
    Tag = EncryptedText[-16:]
    Cipher = AES.new(Key, AES.MODE_GCM, nonce=IV)
    DecryptedText = Cipher.decrypt_and_verify(EncryptedText[AES.block_size:-16], Tag)
    return DecryptedText.decode('utf-8')