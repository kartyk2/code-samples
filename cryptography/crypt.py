import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


enc_password = b"hello there, hi from the password"


def generate_salt() -> bytes:
    """
    Generate a random salt for key derivation.
    """
    return os.urandom(16)


def get_key(salt: bytes) -> bytes:
    """
    Derive a key from the password and salt using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = kdf.derive(enc_password)
    return key


def generate_iv() -> bytes:
    """
    Generate a random IV for AES encryption.
    """
    return os.urandom(16)


def create_hmac(key: bytes, data: bytes) -> bytes:
    """
    Create an HMAC for the given data using the provided key.
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def verify_hmac(key: bytes, data: bytes, tag: bytes) -> bool:
    """
    Verify the HMAC for the given data and tag.
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(tag)
        return True
    except Exception as e:
        print("HMAC verification failed:", str(e))
        return False


def encrypt(data: bytes) -> str:
    """
    Encrypt the data using AES with CBC mode and return it along with the salt, IV, and HMAC.
    """
    # Generate salt and derive key
    salt = generate_salt()
    key = get_key(salt)

    # Generate IV
    iv = generate_iv()

    # Create AES cipher with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad data to the block size of 128 bits
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the padded data
    enc_bytes = encryptor.update(padded_data) + encryptor.finalize()

    # Create HMAC for the encrypted data
    hmac_tag = create_hmac(key, salt + iv + enc_bytes)

    # Encode the result with the salt, IV, HMAC tag, and encrypted data
    result = base64.b64encode(salt + iv + hmac_tag + enc_bytes).decode()
    return result


def decrypt(enc_data: str) -> bytes:
    """
    Decrypt the data after verifying HMAC using AES with CBC mode.
    """
    # Decode and extract salt, IV, HMAC, and encrypted data
    decoded_data = base64.b64decode(enc_data)
    salt = decoded_data[:16]
    iv = decoded_data[16:32]
    hmac_tag = decoded_data[32:64]
    enc_bytes = decoded_data[64:]

    # Derive the same key used for encryption
    key = get_key(salt)

    # Verify HMAC
    if verify_hmac(key, salt + iv + enc_bytes, hmac_tag):
        # Create AES cipher with CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        padded_data = decryptor.update(enc_bytes) + decryptor.finalize()

        # Unpad the decrypted data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

        return decrypted_data
    else:
        raise ValueError("HMAC verification failed. Data may have been tampered with.")


# Example usage
plaintext = b"This is a secret message."

# Encrypt the data
encrypted_data = encrypt(plaintext)
print("Encrypted data:", encrypted_data)

# Decrypt the data
try:
    decrypted_data = decrypt(encrypted_data)
    print("Decrypted data:", decrypted_data.decode())
except ValueError as e:
    print(str(e))
