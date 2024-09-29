import os
import base64
import hashlib
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

    def export_public_key(self):
        # Export the public key in PEM encoding with SPKI 
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
        
    def calculate_fingerprint(self):
        # Calculate the fingerprint of the public key
        public_key_bytes = self.export_public_key()
        return base64.b64encode(hashlib.sha256(public_key_bytes).digest()).decode()

    def symmetric_encrypt(self, message):
        # Perform symmetric decryption using AES-GCM
        key = AESGCM.generate_key(bit_length=128)
        aesgcm = AESGCM(key)
        iv = os.urandom(16)
        ciphertext_and_tag = aesgcm.encrypt(iv, message, None)
        
        # Separate ciphertext and tag
        ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]
        
        return key, iv, ciphertext, tag

    def symmetric_decrypt(self, key, iv, ciphertext, tag):
        # Perform symmetric decryption using AES-GCM
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ciphertext + tag, None)

    def encrypt_message(self, message, recipient_public_key):
        # Encrypt a message using hybrid encryption (symmetric + asymmetric)

        # Symmetric encryption
        sym_key, iv, encrypted_message, tag = self.symmetric_encrypt(message.encode())
        
        # Asymmetric encryption of symmetric key
        encrypted_sym_key = self.asymmetric_encrypt(sym_key, recipient_public_key)
        
        # Sign the encrypted message and tag
        signature = self.sign(encrypted_message + tag)
        
        # Return all necessary components for decryption and verification
        return {
            "iv": base64.b64encode(iv).decode(),
            "symm_key": base64.b64encode(encrypted_sym_key).decode(),
            "encrypted_message": base64.b64encode(encrypted_message).decode(),
            "tag": base64.b64encode(tag).decode(),
            "signature": base64.b64encode(signature).decode()
        }

    def decrypt_message(self, encrypted_data, sender_public_key):
        # Decrypt a message using hybrid encryption (symmetric + asymmetric)

        # Convert base64 strings back to bytes
        iv = base64.b64decode(encrypted_data["iv"])
        encrypted_sym_key = base64.b64decode(encrypted_data["symm_key"])
        encrypted_message = base64.b64decode(encrypted_data["encrypted_message"])
        tag = base64.b64decode(encrypted_data["tag"])
        signature = base64.b64decode(encrypted_data["signature"])

        # Verify signature
        if not self.verify(encrypted_message + tag, signature, sender_public_key):
            raise ValueError("Invalid signature")

        # Decrypt symmetric key
        sym_key = self.asymmetric_decrypt(encrypted_sym_key)

        # Decrypt message using symmetric key
        decrypted_message = self.symmetric_decrypt(sym_key, iv, encrypted_message, tag)

        # Return the decrypted message
        return decrypted_message.decode()
    

def test_crypto():
    print("Testing Crypto class...")

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
    original_message = "This is a test message."
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