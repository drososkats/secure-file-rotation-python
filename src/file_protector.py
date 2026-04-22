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
    
    def protect_file(self, file_path: str, passphrase: str):
        # Generate unique random values for this ops
        # Salt is for the Master Key, Nonce is for the File Key (rotation)
        salt = os.urandom(16)
        nonce = os.urandom(12) # Standard size for GCM and ChaCha20Poly1305

        # Derive the keys using our KDF Engine 
        master_key = self._derive_master_key(passphrase, salt)
        file_key = self._derive_file_key(master_key, nonce)

        # Read the original content
        with open(file_path, "rb") as f:
            plaintext = f.read()
        
        # Initialize the chosen algorithm (Cryptography Agility)
        if self.algorithm == "AES-GCM":
            cipher = AESGCM(file_key)
        else:
            cipher = ChaCha20Poly1305(file_key)
        
        # Encrypt and get the Integrity TAG (AEAD)
        ciphertext = cipher.encrypt(nonce, plaintext, None)

        #Build the protected file (Header + Ciphertext) - store them for the decryption 
        with open(file_path + ".enc", "wb") as f:
            f.write(salt)  # 16 bytes
            f.write(nonce) # 12 bytes
            f.write(ciphertext)

        print(f"[+] File '{file_path}' is now protected.")
        print(f" Algorithm used: {self.algorithm}")

    def unprotect_file(self, file_path: str, passphrase: str):
        # Open the protected file and read the Header metadata
        with open(file_path, "rb") as f:
            salt = f.read(16)      # Read the exact 16 bytes we stored
            nonce = f.read(12)     # Read the exact 12 bytes
            ciphertext = f.read()  # Everything else is the encrypted data + tag
            
        # Re-derive the keys using the salt/nonce from the file (Key Rotation logic)
        master_key = self._derive_master_key(passphrase, salt)
        file_key = self._derive_file_key(master_key, nonce)
        
        # Setup the algorithm for decryption (Crypto-Agility)
        if self.algorithm == "AES-GCM":
            cipher = AESGCM(file_key)
        else:
            cipher = ChaCha20Poly1305(file_key)
            
        try:
            # Decrypt and Verify Integrity (AEAD process)
            # If a single bit has changed, this will raise an InvalidTag exception
            decrypted_data = cipher.decrypt(nonce, ciphertext, None)
            
            # Restore the file to its original state
            output_path = file_path.replace(".enc", "")
            # We add a prefix for now to see both files in our folder
            restored_file = "restored_" + output_path 
            
            with open(restored_file, "wb") as f:
                f.write(decrypted_data)
                
            print(f"[+] Integrity Verified! File restored as: {restored_file}")
            
        except InvalidTag:
            # This is the "Integrity Failure" branch of your diagram
            print("[!] Critical Error: Integrity check failed!")
            print("    Possible causes: Wrong password or file tampering detected.")

if __name__ == "__main__":
    # Quick sanity check
    protector = SecureFileProtector(algorithm="AES-GCM", key_size=256)
    #protector = SecureFileProtector(algorithm="CHACHA20", key_size=128)
    #print(f"[+] Engine initialized. Algorithm: {protector.algorithm}, Key size: {protector.key_size_bits}-bit")
    # Test the encryption 
    test_password = "my_password"
    #protector.protect_file("secret.txt", test_password)
    protector.unprotect_file("secret.txt.enc", test_password)

