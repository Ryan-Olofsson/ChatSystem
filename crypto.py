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
        try:
            # Encrypt a message using RSA with OAEP padding
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
        try:
            # Sign a message using RSA with PSS padding
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
        try:
            # Perform symmetric decryption using AES-GCM
            key = AESGCM.generate_key(bit_length=128)
            aesgcm = AESGCM(key)
            iv = os.urandom(16)
            ciphertext_and_tag = aesgcm.encrypt(iv, message, None)
            
            return key, iv, ciphertext_and_tag
        
        except Exception as e:
            print(f"Failed to encrypt message: {e}")
            raise

    def symmetric_decrypt(self, key, iv, ciphertext):
        try:
            # Perform symmetric decryption using AES-GCM
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(iv, ciphertext, None)
    
        except Exception as e:
            print(f"Failed to decrypt message: {e}")
            raise



    def group_symmetric_encrypt(self, content, key, iv):
        try:
            # Encrypts both the participants and message based off the key and iv of the first encryption
            aesgcm = AESGCM(key)
            return aesgcm.encrypt(iv, content, None)
    
        except Exception as e:
            print(f"Failed to encrypt data: {e}")
            raise
    


    def encrypt_message(self, message, recipient_public_key):
        # Encrypt a message using hybrid encryption (symmetric + asymmetric)
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

    # def decrypt_message(self, fingerprint, encrypted_data):
    #     # Decrypt a message using hybrid encryption (symmetric + asymmetric)

        

    #     # If none of the fingerprints can be decrypted using any of the symmetric keys, return None for both variables
    #     return None, None

    #     # # Decrypt message using symmetric key
    #     # decrypted_message = self.symmetric_decrypt(sym_key, iv, encrypted_message)

    #     # # Return the decrypted message
    #     # return decrypted_message.decode()

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



# def test_crypto():
#     print("Testing Crypto class...")

#     # Create instances for sender and recipient
#     sender = Crypto()
#     recipient = Crypto()

#     # Export public keys
#     sender_public_key = export_public_key(sender.public_key)
#     recipient_public_key = export_public_key(recipient.public_key)

#     print("\nSender's public key:")
#     print(sender_public_key.decode())

#     print("\nRecipient's public key:")
#     print(recipient_public_key.decode())

#     # Test message
#     original_message = "This is a test message."
#     print(f"\nOriginal message: {original_message}")

#     # Encrypt message
#     encrypted_data = sender.encrypt_message(original_message, serialization.load_pem_public_key(recipient_public_key))

#     print("\nEncrypted data:")
#     for key, value in encrypted_data.items():
#         print(f"{key}: {value[:64]}{'...' if len(value) > 64 else ''}")

#     # Decrypt message
#     decrypted_message = recipient.decrypt_message(encrypted_data, calculate_fingerprint(serialization.load_pem_public_key(recipient_public_key)))

#     print(f"\nDecrypted message: {decrypted_message}")

#     # Verify that the decrypted message matches the original
#     assert original_message == decrypted_message, "Decryption failed: messages don't match"
#     print("\nTest passed: Original and decrypted messages match.")

# if __name__ == "__main__":
#     test_crypto()