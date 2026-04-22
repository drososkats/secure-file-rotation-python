import os
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

class SecureFileProtector:
    
    def __init__(self, algorithm: str = "AES-GCM", key_size: int = 256):
        # Crypto-agility config
        self.algorithm = algorithm.upper()
        self.key_size_bits = key_size
        self.key_size_bytes = key_size // 8
        
        # Standard iterations for PBKDF2 against brute-force attacks
        self.kdf_iterations = 600_000 
        
        # Enforce ChaCha20 specs (strictly requires 256-bit key)
        if self.algorithm == "CHACHA20" and self.key_size_bits != 256:
            self.key_size_bits = 256
            self.key_size_bytes = 32

    def _derive_master_key(self, passphrase: str, salt: bytes) -> bytes:
        # Generate the main key from user's passphrase
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size_bytes,
            salt=salt,
            iterations=self.kdf_iterations,
        )
        return kdf.derive(passphrase.encode('utf-8'))

    def _derive_file_key(self, master_key: bytes, nonce: bytes) -> bytes:
        # Generate a unique key per file using the nonce (Key Rotation core logic)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size_bytes,
            salt=nonce,
            iterations=1, # Master key is already strong, 1 iteration is sufficient
        )
        return kdf.derive(master_key)

if __name__ == "__main__":
    # Quick sanity check
    protector = SecureFileProtector(algorithm="AES-GCM", key_size=256)
    #protector = SecureFileProtector(algorithm="CHACHA20", key_size=128)
    print(f"[+] Engine initialized. Algorithm: {protector.algorithm}, Key size: {protector.key_size_bits}-bit")