import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Crypto:
    def __init__(self):
        # Generate a new RSA private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # Extract the public key from the private key
        self.public_key = self.private_key.public_key()

    def export_public_key(self):
        # Export the public key in PEM format
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def asymmetric_encrypt(self, message, public_key):
        # Encrypt a message using RSA with OAEP padding
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

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
        return self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )

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
        except:
            return False

    def symmetric_encrypt(self, message):
        # Perform symmetric encryption using AES-GCM
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)
        iv = os.urandom(16)
        ciphertext = aesgcm.encrypt(iv, message, None)
        return key, iv, ciphertext

    def symmetric_decrypt(self, key, iv, ciphertext):
        # Perform symmetric decryption using AES-GCM
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ciphertext, None)

    def encrypt_message(self, message, recipient_public_key):
        # Encrypt a message using hybrid encryption (symmetric + asymmetric)
        # Symmetric encryption
        sym_key, iv, encrypted_message = self.symmetric_encrypt(message.encode())
        
        # Asymmetric encryption of symmetric key
        encrypted_sym_key = self.asymmetric_encrypt(sym_key, recipient_public_key)
        
        # Sign the encrypted message
        signature = self.sign(encrypted_message)
        
        # Return all necessary components for decryption and verification
        return {
            "iv": iv.hex(),
            "symm_key": encrypted_sym_key.hex(),
            "encrypted_message": encrypted_message.hex(),
            "signature": signature.hex()
        }

    def decrypt_message(self, encrypted_data, sender_public_key):
        # Decrypt a message using hybrid encryption (symmetric + asymmetric)
        # Convert hex strings back to bytes
        iv = bytes.fromhex(encrypted_data["iv"])
        encrypted_sym_key = bytes.fromhex(encrypted_data["symm_key"])
        encrypted_message = bytes.fromhex(encrypted_data["encrypted_message"])
        signature = bytes.fromhex(encrypted_data["signature"])

        # Verify signature
        if not self.verify(encrypted_message, signature, sender_public_key):
            raise ValueError("Invalid signature")

        # Decrypt symmetric key
        sym_key = self.asymmetric_decrypt(encrypted_sym_key)

        # Decrypt message
        decrypted_message = self.symmetric_decrypt(sym_key, iv, encrypted_message)

        return decrypted_message.decode()
    

def test_crypto():
    print("Testing OlafCrypto class...")

    # Create instances for sender and recipient
    sender = Crypto()
    recipient = Crypto()

    # Export public keys
    sender_public_key = sender.export_public_key()
    recipient_public_key = recipient.export_public_key()

    print("\nSender's public key:")
    print(sender_public_key.decode())

    print("\nRecipient's public key:")
    print(recipient_public_key.decode())

    # Test message
    original_message = "Hello, Olaf! This is a test message."
    print(f"\nOriginal message: {original_message}")

    # Encrypt message
    encrypted_data = sender.encrypt_message(original_message, serialization.load_pem_public_key(recipient_public_key))

    print("\nEncrypted data:")
    for key, value in encrypted_data.items():
        print(f"{key}: {value[:64]}{'...' if len(value) > 64 else ''}")

    # Decrypt message
    decrypted_message = recipient.decrypt_message(encrypted_data, serialization.load_pem_public_key(sender_public_key))

    print(f"\nDecrypted message: {decrypted_message}")

    # Verify that the decrypted message matches the original
    assert original_message == decrypted_message, "Decryption failed: messages don't match"
    print("\nTest passed: Original and decrypted messages match.")

if __name__ == "__main__":
    test_crypto()