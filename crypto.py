# Ryan Olofsson a1864245, Tyler Chapman 1851834, Kian Esmailzadeh a1851935
import os
import base64
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Crypto:
    def __init__(self):
        # Generate a new RSA private key using the required parameters
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Extract the public key from the private key
        self.public_key = self.private_key.public_key()



    def asymmetric_encrypt(self, sym_key, public_key):
        # Encrypt a message using RSA with OAEP padding
        try:
            return public_key.encrypt(
                sym_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            print(f"Failed to encrypt key: {e}")
            raise 

    def asymmetric_decrypt(self, ciphertext):
        # Decrypt a message using RSA with OAEP padding
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )



    def sign(self, message):
        # Sign a message using RSA with PSS padding
        try:
            return self.private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32
                ),
                hashes.SHA256()
            )
    
        except Exception as e:
            print(f"Failed to sign message: {e}")
            raise

    def verify(self, message, signature, public_key):
        # Verify a signature using RSA with PSS padding
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Failed to verify message signature: {e}")
            return False



    def symmetric_encrypt(self, message):
        # Perform symmetric decryption using AES-GCM
        try:
            key = AESGCM.generate_key(bit_length=128)
            aesgcm = AESGCM(key)
            iv = os.urandom(16)
            ciphertext_and_tag = aesgcm.encrypt(iv, message, None)
            
            return key, iv, ciphertext_and_tag
        
        except Exception as e:
            print(f"Failed to encrypt message: {e}")
            raise

    def symmetric_decrypt(self, key, iv, ciphertext):
        # Perform symmetric decryption using AES-GCM
        try:
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(iv, ciphertext, None)
    
        except Exception as e:
            print(f"Failed to decrypt message: {e}")
            raise



    def group_symmetric_encrypt(self, content, key, iv):
        # Encrypts both the participants and message based off the key and iv of the first encryption
        try:
            aesgcm = AESGCM(key)
            return aesgcm.encrypt(iv, content, None)
        except Exception as e:
            print(f"Failed to encrypt data: {e}")
            raise
    

    # Encrypt a message using hybrid encryption (symmetric + asymmetric)
    def encrypt_message(self, message, recipient_public_key):
        
        # Symmetric encryption
        sym_key, iv, encrypted_message = self.symmetric_encrypt(message.encode())
        
        # Asymmetric encryption of symmetric key
        encrypted_sym_key = self.asymmetric_encrypt(sym_key, recipient_public_key)
        
        # Return all necessary components for decryption and verification
        return {
            "iv": iv,
            "encrypted_symm_key": base64.b64encode(encrypted_sym_key).decode(),
            "encrypted_message": base64.b64encode(encrypted_message).decode(),
            "symm_key": sym_key
        }

    def encrypt_key(self, sym_key, recipient_public_key):
        # Asymmetric encryption of symmetric key
        encrypted_sym_key = self.asymmetric_encrypt(sym_key, recipient_public_key)

        return base64.b64encode(encrypted_sym_key).decode()


def export_public_key(public_key):
    # Export the public key in PEM encoding with SPKI 
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def calculate_fingerprint(public_key):
    # Calculate the fingerprint of the public key
    public_key_bytes = export_public_key(public_key)
    return base64.b64encode(hashlib.sha256(public_key_bytes).digest()).decode()