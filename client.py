# Ryan Olofsson a1864245, Tyler Chapman 1851834, Kian Esmailzadeh a1851935
import json
import base64
import re
from crypto import Crypto, calculate_fingerprint, export_public_key
from cryptography.hazmat.primitives import serialization
from chatapp.serverFunctions import send_all_clients
from chatapp.extensions import socketio
from flask_socketio import emit


class Client:
    # Init for client
    def __init__(self, username):
        self.server_address = None
        self.username = username
        self.crypto = Crypto()
        self.fingerprint = calculate_fingerprint(self.crypto.public_key)
        self.counter = 0
        self.received_counters = {}  # To track counters for each sender
        

    # Send a signed hello message
    def send_hello(self):
        try: 
            hello_message = self.create_signed_message({
                "type": "hello",
                "public_key": export_public_key(self.crypto.public_key).decode()
            })

            # Send the hello message
            socketio.emit('signed_data_hello', hello_message)
        except Exception as e:
            print(f"Failed to send hello message: {e}")

    # Create a signed message with counter to prevent replay attacks
    def create_signed_message(self, data):
        try:
            message = {
                "type": "signed_data",
                "data": data,
                "counter": self.counter
            }

            # Sign data and encode signature
            signature = self.crypto.sign((json.dumps(data) + str(self.counter)).encode())
            message["signature"] = base64.b64encode(signature).decode()

            # Iterate counter and return the signed message
            self.counter += 1
            return message
        except Exception as e:
            print(f"Failed to sign message: {e}")
            raise

    # Encrypt and send a chat message to specified recipients
    def send_chat_message(self, message, recipients, destination_servers):
        try:
            # Message sanitisation
            message = re.sub(r'[^\w\s]', '', message)

            # Define chat content and chat data lists with entries matching the specification
            chat_content = {
                "participants": [],
                "message": message
            }

            chat_data = {
                "type": "chat",
                "destination_servers": destination_servers,
                "symm_keys": [],
                "iv": None,
                "chat": chat_content
            }

            # Set variable for initialising the iv and symm_key
            first = True
            sym_key = None
            iv = None

            # Loop through all recipients and get the public keys
            for recipient in recipients:
                recipient_public_key = serialization.load_pem_public_key(recipient)

                # If its the first recipient, then encrypt the message, then extract and append the iv and sym_key
                if first:
                    encrypted_data = self.crypto.encrypt_message(message, recipient_public_key)

                    iv = encrypted_data["iv"]
                    chat_data["iv"] = base64.b64encode(encrypted_data["iv"]).decode()

                    sym_key = encrypted_data["symm_key"]
                    chat_data["symm_keys"].append(encrypted_data["encrypted_symm_key"])
                    first = False

                # For all other recipeints, encrypt the sym_key using their public key and append it to symm_keys
                else:
                    encrypted_sym_key = self.crypto.asymmetric_encrypt(sym_key, recipient_public_key)
                    chat_data["symm_keys"].append(base64.b64encode(encrypted_sym_key).decode())

            # Encrypt  the message using the symmetric key
            chat_content["message"] = base64.b64encode(self.crypto.group_symmetric_encrypt(message.encode(), sym_key, iv)).decode()

            # Encrypt the fingerprint of the sender and append to participants
            encrypted_participant = self.crypto.group_symmetric_encrypt(self.fingerprint.encode(), sym_key, iv)
            chat_content["participants"].append(base64.b64encode(encrypted_participant).decode())

            # Encrypt the fingerprints of all recipients and append to participants
            for recipient in recipients:
                recipient_public_key = serialization.load_pem_public_key(recipient)
                encrypted_participant = self.crypto.group_symmetric_encrypt(calculate_fingerprint(recipient_public_key).encode(), sym_key, iv)
                chat_content["participants"].append(base64.b64encode(encrypted_participant).decode())
            
            # Sign the message
            chat_data = self.create_signed_message(chat_data)

            # Return the signed message
            return(chat_data)

        except Exception as e:
            print(f"Failed to send chat message: {e}")
            raise

    # Send a public chat message visible to all clients
    def send_public_chat_message(self, message):

        # Message sanitisation
        message = re.sub(r'[^\w\s]', '', message)

        public_chat_message = self.create_signed_message({
            "type": "public_chat",
            "sender": self.fingerprint,
            "message": message
        })

        # Emit public chat
        socketio.emit('signed_data_public', public_chat_message)

    # Handles messages forwarded by the server
    def process_signed_message(self, message):
        try:
            # Check to see if the message is signed data
            if message['type'] != 'signed_data':
                print(f"Received unknown message type: {message['type']}")
                return

            # Get message data
            data = message['data']
            counter = message['counter']
            signature = base64.b64decode(message['signature'])

            sender_fingerprint = None
            decrypted_message = None

            # Get fingerprint of sender if the client is the intended reciever, different methods depending on data type
            if data['type'] == 'chat':

                # Convert base64 strings back to bytes
                iv = base64.b64decode(data["iv"])

                chat_content = data["chat"]
                participants = chat_content['participants']

                # Loop through all symmetric keys
                for b64_sym_key in data['symm_keys']:

                    # Decode symmetric key and try to decrypt using private key
                    encrypted_sym_key = base64.b64decode(b64_sym_key)
                    try:
                        sym_key = self.crypto.asymmetric_decrypt(encrypted_sym_key)
                    except Exception as e:
                        continue

                    # Loop through all participant's fingerprints
                    for participant in participants:
                        participant = base64.b64decode(participant)

                        try:
                            # Decrypt the fingerprint using the symmetric key and iv
                            test_fingerprint = self.crypto.symmetric_decrypt(sym_key, iv, participant)

                            # Check if the decrypted fingerprit is the client's fingerprint
                            if test_fingerprint.decode() == self.fingerprint:

                                # Decrypt the message and return the sender fingerprint and decrypted message
                                decrypted_message = self.crypto.symmetric_decrypt(sym_key, iv, base64.b64decode(chat_content["message"]))
                                sender_fingerprint = self.crypto.symmetric_decrypt(sym_key, iv, base64.b64decode(participants[0])).decode()
                                decrypted_message = decrypted_message.decode()
                                break
                        except Exception as e:
                            continue 

                # Return if client isn't intended receiver
                if sender_fingerprint == None:
                    print("Received chat message not intended for this client")
                    return
            elif data['type'] == 'public_chat':
                sender_fingerprint = data['sender']

            # Get public key matching the fingerprint of the sender
            sender_public_key = None
            all_clients = send_all_clients()
            sender_public_key = all_clients.get(sender_fingerprint)

            # Return if the fingerprint of sender can't be found in the client list
            if sender_public_key == None:
                print("Received chat message not intended for this client")
                return

            # Convert the public key into a format acceptable for the verification 
            try:
                sender_public_key = sender_public_key.encode()
                sender_public_key = serialization.load_pem_public_key(sender_public_key)    
            except Exception as e:
                print(f"Failed to load public key: {e}")
                return

            # Verify the signature of the message
            if not self.crypto.verify(json.dumps(data).encode() + str(counter).encode(), signature, sender_public_key):
                print("Signature verification failed.")
                return
            
            
            # Verify the counter of the message
            if not self.verify_counter(sender_fingerprint, counter):
                print("Invalid counter value, possible replay attack")
                return
            
            # Print the message if the client is intended recipient, signature is verified and the counter is verified
            if data['type'] == 'public_chat':
                print(f"Received public chat message: {data['message']}")
            elif data['type'] == 'chat':
                print(f"Received chat message from {sender_fingerprint}: {decrypted_message}")

            # Return the decrypted message
            return decrypted_message

        except Exception as e:
            print(f"Failed to process message: {e}")

    def verify_counter(self, counter, sender_fingerprint):
        # Verify that the message counter is greater than the last received counter
        last_counter = self.received_counters.get(sender_fingerprint)

        if not last_counter:
            self.received_counters[sender_fingerprint] = counter
            return True

        if counter > last_counter:
            self.received_counters[sender_fingerprint] = counter
            return True
        return False