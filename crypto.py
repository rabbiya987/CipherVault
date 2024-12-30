import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
import base64

# XOR Encryption/Decryption
def XOR(text, decrypt=False, key='k'):
    return ''.join([chr(ord(char) ^ ord(key)) for char in text])

# Caesar Cipher Encryption/Decryption
def CaesarCipher(text, decrypt=False):
    shift = 7  # Fixed shift for Caesar cipher
    if decrypt:
        shift = -shift  # Reverse the shift for decryption
    
    result = ''.join(
        chr(((ord(char) - 97 + shift) % 26) + 97) if char.islower() else
        chr(((ord(char) - 65 + shift) % 26) + 65) if char.isupper() else char
        for char in text
    )
    return result

# Base64 Encryption/Decryption
def Base64Cipher(text, decrypt=False):
    try:
        if decrypt:
            decoded_bytes = base64.b64decode(text.encode('utf-8'))
            return decoded_bytes.decode('utf-8')
        else:
            encoded_bytes = base64.b64encode(text.encode('utf-8'))
            return encoded_bytes.decode('utf-8')
    except Exception as e:
        return f"Error during Base64 operation: {e}"

# MD5 Hashing (One-way only, so no decrypt)
def MD5(text, decrypt=False):
    if decrypt:
        return "MD5 cannot be decrypted; it is a one-way hashing algorithm."
    hash_object = hashlib.md5(text.encode('utf-8'))
    return hash_object.hexdigest()

# SHA-565 Hashing (Simulated by running SHA-256 twice, One-way only)
def SHA565(text, decrypt=False):
    if decrypt:
        return "SHA-565 cannot be decrypted; it is a one-way hashing algorithm."
    hash_object = hashlib.sha256(text.encode('utf-8'))
    hash_once = hash_object.hexdigest()
    hash_twice = hashlib.sha256(hash_once.encode('utf-8')).hexdigest()
    return hash_twice

# AES Encryption/Decryption
def AES_Cipher(text, decrypt=False, key='thisisaverysecurekey'):
    key = key[:16].encode('utf-8')  # AES requires a 16-byte key
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    try:
        if decrypt:
            decrypted = unpad(cipher.decrypt(base64.b64decode(text)), AES.block_size)
            return decrypted.decode('utf-8')
        else:
            padded_text = pad(text.encode('utf-8'), AES.block_size)
            encrypted = base64.b64encode(cipher.encrypt(padded_text)).decode('utf-8')
            return encrypted
    except Exception as e:
        return f"Error in AES operation: {e}"


