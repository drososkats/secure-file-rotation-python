import os
import getpass
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidTag, InvalidSignature

class SecureFileProtector:
    """
    A cryptographic toolkit for file protection.
    Implements multiple security modes: Confidentiality, Integrity, and AEAD.
    Uses Argon2id for key derivation and supports key rotation.
    """
    def __init__(self, algorithm="AES-GCM", key_size=256):
        self.algorithm = algorithm
        self.key_size = key_size # 128 or 256 bits

    def _derive_master_key(self, passphrase: str, salt: bytes) -> bytes:
        """
        KDF Engine: pwd --> KDF --> Argon2id
        Transforms a passphrase into a cryptographic master key.
        Uses Argon2id (memory-hard, resistant to GPU/ASIC cracking).
        """
        # Argon2id parameters (3 iterations, 64MB memory, 4 parallel threads)
        master_key = low_level.hash_secret_raw(
            secret=passphrase.encode(),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32, # output 256 bits, then truncate if needed
            type=low_level.Type.ID
        )
        # handle key size (128 bits = 16 bytes, 256 bits = 32 bytes)
        return master_key[:self.key_size // 8]

    # MODE 3: Confidentiality & Integrity (AES-GCM / ChaCha20-Poly1305)
    def protect_file(self, file_path: str, passphrase: str, data_override=None, delete_after=False):
        """
        Encrypts a file using AEAD (AES-GCM or ChaCha20-Poly1305).
        Implements salt and nonce as Associated Data (AD) for metadata integrity.
        """
        salt = os.urandom(16)
        nonce = os.urandom(12) 
        key = self._derive_master_key(passphrase, salt)
        
        if data_override:
            data = data_override
        else:
            with open(file_path, "rb") as f:
                data = f.read()

        # Bind salt and nonce to the ciphertext using Associated Data (AD)
        # This ensures metadata integrity; tampering with salt/nonce will cause decryption failure.
        associated_data = salt + nonce

        if self.algorithm == "AES-GCM":
            cipher = AESGCM(key)
        else:
            cipher = ChaCha20Poly1305(key)
            
        # Encrypt the data and generate the authentication tag
        ciphertext = cipher.encrypt(nonce, data, associated_data)

        with open(file_path + ".enc", "wb") as f:
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)
        print(f"[+] Mode 3 ({self.algorithm}) complete: {file_path}.enc (Metadata Integrity Secured)")

        # delete only if requested and NOT an internal rotation call
        if delete_after and not data_override:
            if os.path.exists(file_path):
                os.remove(file_path)
                print("[+] Original file deleted for security.")

    def unprotect_file(self, file_path: str, passphrase: str):
        """
        Decrypts an AEAD file, verifies integrity, and AUTOMATICALLY rotates the key.
        This fulfills the requirement: 'key changes every time decryption occurs'.
        """
        try:
            with open(file_path, "rb") as f:
                salt = f.read(16)
                nonce = f.read(12)
                ciphertext = f.read()

            key = self._derive_master_key(passphrase, salt)
            associated_data = salt + nonce
            
            if self.algorithm == "AES-GCM":
                cipher = AESGCM(key)
            else:
                cipher = ChaCha20Poly1305(key)
                
            decrypted_data = cipher.decrypt(nonce, ciphertext, associated_data)

            # Save the restored plaintext
            output_path = file_path.replace(".enc", ".restored")
            with open(output_path, "wb") as f:
                f.write(decrypted_data)
            print(f"[+] Integrity Verified! Content restored to: {output_path}")

            # AUTOMATIC KEY ROTATION:
            # Re-encrypt the original file with a NEW salt/key immediately.
            original_path = file_path.replace(".enc", "")
            print("[*] Triggering automatic key rotation...")
            self.protect_file(original_path, passphrase, data_override=decrypted_data)
            print("[+] Key automatically rotated successfully.")
        except InvalidTag:
            print("[!] Authentication Failed: Wrong password or corrupted metadata.")
        except Exception as e:
            print(f"[!] Unexpected Error: {e}")

    # MODE 2: Integrity Only (HMAC-SHA256)
    def sign_file(self, file_path: str, passphrase: str, delete_after=False):
        """
        Generates a digital signature for a file using HMAC-SHA256.
        Plaintext remains visible, but tampering is detectable.
        """
        salt = os.urandom(16)
        key = self._derive_master_key(passphrase, salt)
        
        with open(file_path, "rb") as f:
            data = f.read()

        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        signature = h.finalize()

        with open(file_path + ".sig", "wb") as f:
            f.write(salt)
            f.write(signature)
            f.write(data)
        print(f"[+] Mode 2 (Integrity) complete: {file_path}.sig")
        if delete_after:
            if os.path.exists(file_path):
                os.remove(file_path)
                print("[+] Original file deleted for security.")

    def verify_file(self, file_path: str, passphrase: str):
        """
        Verifies the digital signature of a file and automatically rotates the integrity key.
        This ensures that even a simple integrity check triggers a key refresh.
        """
        try:
            # 1. Read the existing .sig file
            with open(file_path, "rb") as f:
                salt = f.read(16)
                signature = f.read(32)
                data = f.read()

            # 2. Derive the key using the stored salt and verify integrity
            key = self._derive_master_key(passphrase, salt)
            h = hmac.HMAC(key, hashes.SHA256())
            h.update(data)
            
            # This will raise an exception if the signature is invalid
            h.verify(signature)
            
            print("[+] Signature Valid! Integrity Confirmed.")

            # AUTOMATIC KEY ROTATION
            # Since the original plaintext file might be deleted, we recreate it 
            # temporarily to allow sign_file to perform a fresh rotation.
            temp_plaintext_path = file_path.replace(".sig", "")
            
            with open(temp_plaintext_path, "wb") as f:
                f.write(data)
            
            print("[*] Triggering automatic integrity key rotation...")
            # sign_file will generate a NEW salt and NEW signature
            self.sign_file(temp_plaintext_path, passphrase)
            
            # Clean up the temporary plaintext file
            if os.path.exists(temp_plaintext_path):
                os.remove(temp_plaintext_path)
                
            print("[+] Integrity key automatically rotated and metadata updated.")

        except InvalidSignature:
            print("[!] CRITICAL: Signature Verification Failed! The file has been tampered with or the password is wrong.")
        except Exception as e:
            print(f"[!] File Error: {e}")

    # MODE 1: Confidentiality Only (AES-CTR)
    def protect_confidentiality_only(self, file_path: str, passphrase: str, delete_after=False):
        """
        Encrypts a file using AES-CTR. 
        Note: This mode lacks an authentication tag (No Integrity Protection).
        """
        salt = os.urandom(16)
        nonce = os.urandom(16)
        key = self._derive_master_key(passphrase, salt)
        
        with open(file_path, "rb") as f:
            data = f.read()

        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        with open(file_path + ".ctr", "wb") as f:
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)
        print(f"[+] Mode 1 (CTR) complete: {file_path}.ctr")
        if delete_after:
            if os.path.exists(file_path):
                os.remove(file_path)
                print("[+] Original file deleted for security.")

    def unprotect_confidentiality_only(self, file_path: str, passphrase: str):
        """
        Decrypts an AES-CTR file. Note: No integrity check is possible in this mode.
        """
        try:
            with open(file_path, "rb") as f:
                salt = f.read(16)
                nonce = f.read(16)
                ciphertext = f.read()

            key = self._derive_master_key(passphrase, salt)
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            output_path = file_path.replace(".ctr", ".decrypted_ctr")
            with open(output_path, "wb") as f:
                f.write(plaintext)
            
            print(f"[+] Decryption complete: {output_path}")
            print("[!] Note: Integrity was not verified (AES-CTR mode).")

        except FileNotFoundError:
            print(f"[!] Error: File '{file_path}' not found.")
        except Exception as e:
            print(f"[!] System Error during CTR decryption: {e}")

    # KEY ROTATION (Password Change & Re-encryption)
    def rotate_key(self, file_path: str, old_pass: str, new_pass: str):
        """
        Rotates the Master Key by decrypting with old key and re-encrypting with new key.
        Implements the Red Dashed Line in the architecture diagram.
        """
        try:
            with open(file_path, "rb") as f:
                salt = f.read(16)
                nonce = f.read(12)
                ciphertext = f.read()
            
            # Decrypt using the old password and the existing salt as AD
            old_key = self._derive_master_key(old_pass, salt)
            associated_data_old = salt + nonce
            
            if self.algorithm == "AES-GCM":
                cipher = AESGCM(old_key)
            else:
                cipher = ChaCha20Poly1305(old_key)
                
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data_old)
            
            # Re-encrypt with new password (automatically generates fresh salt/nonce)
            original_name = file_path.replace(".enc", "")
            self.protect_file(original_name, new_pass, data_override=plaintext)
            print("[+] Key Rotation Successful! New unique salt and master key generated.")
        except InvalidTag:
            print("[!] Rotation Failed: The old password is incorrect or the file is not a valid encrypted file.")
        except Exception as e:
            print(f"[!] Rotation Error: {e}")

# --- CLI MENU SECTION ---
if __name__ == "__main__":
    print("\n" + "═"*45)
    print("           FILE PROTECTION TOOL")
    print("═"*45)
    
    # Mode Selection with Validation
    while True:
        print("\n[!] Select Mode:")
        print(" 1. Confidentiality (AES-CTR)")
        print(" 2. Integrity (HMAC-SHA256)")
        print(" 3. Confidentiality & Integrity (Combined)")
        print(" 4. Rotate Key / Change Password")
        mode_choice = input("\nEnter selection (1-4): ")
        if mode_choice in ["1", "2", "3", "4"]:
            break
        print("[!] Invalid selection. Please choose 1-4.")
    
    # Algorithm Selection (Only for Combined Protection or Key Rotation)
    selected_algo = "AES-GCM" 
    if mode_choice in ["3", "4"]:
        while True:
            print("\n[!] Select Algorithm:")
            print(" 1. AES-GCM")
            print(" 2. ChaCha20-Poly1305")
            algo_input = input("\nEnter selection (1-2): ")
            if algo_input in ["1", "2"]:
                selected_algo = "AES-GCM" if algo_input == "1" else "ChaCha20-Poly1305"
                break
            print("[!] Invalid selection. Please choose 1 or 2.")

    # Action Selection (Protect vs Unprotect)
    action = None
    if mode_choice != "4":
        while True:
            print("\nChoose Action:")
            print(" [1] Protect/Sign")
            print(" [2] Unprotect/Verify")
            action = input("\nEnter selection (1-2): ")
            if action in ["1", "2"]:
                break
            print("[!] Invalid selection. Please choose 1 or 2.")

    # Secure Deletion Option (Only for Protection/Signing actions)
    delete_original = False
    if action == "1":
        while True:
            choice = input("\nDelete original file after operation? (y/n): ").lower()
            if choice in ['y', 'n']:
                delete_original = (choice == 'y')
                break
            print("[!] Invalid input. Please enter 'y' or 'n'.")
    
    # Security Level Selection (λ = 128 or 256 bits)
    while True:
        print("\n[!] Security Level:")
        print(" [1] 128-bit")
        print(" [2] 256-bit")
        k_choice = input("\nEnter selection (1-2): ")
        if k_choice in ["1", "2"]:
            k_size = 128 if k_choice == "1" else 256
            break
        print("[!] Invalid selection. Please choose 1 or 2.")
    
    # Initialize the protector class based on user choices
    if mode_choice == "1":
        selected_algo = "AES-CTR"
    elif mode_choice == "2":
        selected_algo = "HMAC"
        
    protector = SecureFileProtector(algorithm=selected_algo, key_size=k_size)
    
    # File Path Entry and Execution Logic
    file_path = input("\nEnter file path: ")
    
    if os.path.exists(file_path):
        if mode_choice == "1":
            pwd = getpass.getpass("Password: ")
            if action == "1":
                protector.protect_confidentiality_only(file_path, pwd, delete_after=delete_original)
            else:
                protector.unprotect_confidentiality_only(file_path, pwd)
                
        elif mode_choice == "2":
            pwd = getpass.getpass("Password: ")
            if action == "1":
                protector.sign_file(file_path, pwd, delete_after=delete_original)
            else:
                protector.verify_file(file_path, pwd)
                
        elif mode_choice == "3":
            pwd = getpass.getpass("Password: ")
            if action == "1":
                protector.protect_file(file_path, pwd, delete_after=delete_original)
            else:
                protector.unprotect_file(file_path, pwd)
                
        elif mode_choice == "4":
            old_p = getpass.getpass("Old Password: ")
            new_p = getpass.getpass("New Password: ")
            # Key rotation triggers re-encryption with a fresh salt and new master key
            protector.rotate_key(file_path, old_p, new_p)
    else:
        print("[!] File not found. Please check the path and try again.")