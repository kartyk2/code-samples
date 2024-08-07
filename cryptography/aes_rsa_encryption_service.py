from datetime import timedelta
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

class Encryptor:

    def __init__(self, RSA_PRI_PATH: str, RSA_PUB_PATH: str, timestamp_tolerance_minutes: int = 3, iv_length: int = 12):
        """Initialize the encryption service with RSA keys and timestamp tolerance."""
        self.iv_length = iv_length
        self.private_key= self.load_rsa_private_key(RSA_PRI_PATH)
        self.public_key= self.load_rsa_public_key(RSA_PUB_PATH)
        self.timestamp_tolerance = timedelta(minutes=timestamp_tolerance_minutes)
        self.iv_length = 16

    def load_rsa_private_key(self, file_path: str) -> rsa.RSAPrivateKey:
        """Load the RSA private key from a PEM file."""
        with open(file_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        return private_key

    def load_rsa_public_key(self, file_path: str) -> rsa.RSAPublicKey:
        """Load the RSA public key from a PEM file."""
        with open(file_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key
    
    def decrypt_aes_key(self, encrypted_aes_key_bytes: bytes):
        aes_key = self.private_key.decrypt(
            encrypted_aes_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key

    def encrypt_payload(self, payload: bytes, aes_key: bytes) -> str:
        """Encrypt the payload using AES-GCM with IV as a substring of the AES key."""
        # Use the first `iv_length` bytes of the AES key as the IV
        iv = aes_key[:self.iv_length]
        
        # Create an AES-GCM cipher
        aesgcm = Cipher(
            algorithms.AES(aes_key), 
            modes.GCM(iv, min_tag_length=16), 
            backend=default_backend()
        ).encryptor()
        
        # Encrypt the payload
        encrypted_payload = aesgcm.update(payload) + aesgcm.finalize()
        print(len(encrypted_payload))
        
        # Combine IV, tag, and encrypted payload
        iv_tag_cipher = iv + aesgcm.tag + encrypted_payload
        
        # Encode to base64 for transmission
        encrypted_payload_base64 = base64.b64encode(iv_tag_cipher).decode('utf-8')
        
        # Ensure proper base64 padding if needed
        if len(encrypted_payload_base64) % 4 != 0:
            encrypted_payload_base64 += '=' * (4 - len(encrypted_payload_base64) % 4)
        print(len(encrypted_payload_base64))
        return encrypted_payload_base64

    def decrypt_payload(self, encrypted_payload_base64: str, aes_key: bytes) -> bytes:
        """Decrypt the payload using AES-GCM."""
        # Decode the base64 payload
        iv_tag_cipher = base64.b64decode(encrypted_payload_base64)
        
        # Extract IV, tag, and ciphertext
        iv = iv_tag_cipher[:self.iv_length]
        tag = iv_tag_cipher[self.iv_length:self.iv_length + 16]
        ciphertext = iv_tag_cipher[self.iv_length + 16:]
        
        # Create AES-GCM decryptor
        aesgcm = Cipher(
            algorithms.AES(aes_key), 
            modes.GCM(iv, tag), 
            backend=default_backend()
        ).decryptor()
        
        # Decrypt the ciphertext
        decrypted_payload = aesgcm.update(ciphertext) + aesgcm.finalize()
        
        return decrypted_payload

    def generate_signature(
        self, 
        private_key: RSAPrivateKey, 
        rrn: str, 
        timestamp: str, 
        cipherText: str
    ) -> str:
        """Generate a digital signature using the biller's private key."""
        message = (rrn + timestamp + cipherText).encode('utf-8')
        
        # Sign the message
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Encode the signature to base64
        signature_base64 = base64.b64encode(signature).decode('utf-8')
        
        return signature_base64

    def verify_signature(
        self, 
        public_key: RSAPublicKey, 
        signature_base64: str, 
        rrn: str, 
        timestamp: str, 
        cipherText: str
    ) -> bool:
        """Verify the digital signature using the public key."""
        message = (rrn + timestamp + cipherText).encode('utf-8')
        
        # Decode the signature from base64
        signature = base64.b64decode(signature_base64)
        
        try:
            # Verify the signature
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print("Verification failed:", str(e))
            return False


def main():
    # Example usage of encryption and signature generation
    rrn = "SB5120210212093848ee3b04f1043344f69"
    timeStamp = "2021-02-12T21:38:49+05:30"
    plaintext = b"BBPS Online Biller Integration Kit"

    # Generate a random AES key (256-bit)
    aes_key = os.urandom(32)

    # Create an Encryptor instance
    encryptor = Encryptor()

    # Encrypt the payload
    cipherText = encryptor.encrypt_payload(plaintext, aes_key)
    print("Cipher Text:", cipherText)

    # Generate RSA key pair for signing
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Generate digital signature
    digitalSig = encryptor.generate_signature(private_key, rrn, timeStamp, cipherText)
    print("Digital Signature:", digitalSig)

    # Verify the signature
    is_verified = encryptor.verify_signature(public_key, digitalSig, rrn, timeStamp, cipherText)
    print("Signature Verified:", is_verified)

    # Example of decrypting the payload
    decrypted_payload = encryptor.decrypt_payload(cipherText, aes_key)
    print("Decrypted Payload:", decrypted_payload.decode('utf-8'))


if __name__ == "__main__":
    main()
