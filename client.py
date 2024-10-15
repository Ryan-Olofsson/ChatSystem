# Ryan Olofsson a1864245, Tyler Chapman 1851834, Kian Esmailzadeh a1851935
import json
import base64
import requests
import re
from crypto import Crypto, calculate_fingerprint, export_public_key
from cryptography.hazmat.primitives import serialization
from chatapp.serverFunctions import get_Connected_Clients
from chatapp.extensions import socketio
import socketio as socketio_client


class Client:
    # Server address is useless rn
    def __init__(self, username):
        self.server_address = None
        self.username = username
        self.crypto = Crypto()
        self.fingerprint = calculate_fingerprint(self.crypto.public_key)
        self.counter = 0
        self.received_counters = {}  # To track counters for each sender

        self.sio = socketio_client.Client()
        # self.connect_to_server("http://127.0.0.1:5000")  # Replace with your server address

    def connect_to_server(self, server_address):
        self.sio.connect(server_address)  # Connect to the server
        print(f"Connected to server at {server_address}")

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

            # Message sanitisation, may need to sanitise recipients and destination_servers as well
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
                # Only need to get the iv and sym_key once
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


            # socketio.emit('signed_data_chat', chat_data)

            return json.dumps(chat_data)
        
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

        # socketio.emit('signed_data_public', public_chat_message)
        return json.dumps(public_chat_message)


    # # Should be a JS function
    # def request_client_list(self):
    #     # Request the list of connected clients from the server
    #     request = {
    #         "type": "client_list_request"
    #     }
    #     self.ws.send(json.dumps(request))

    # def upload_file(self, file_path):
    #     # Upload a file to the server
    #     with open(file_path, 'rb') as file:
    #         response = requests.post(f"http://{self.server_address}/api/upload", files={'file': file})
    #     if response.status_code == 200:
    #         return response.json()['file_url']
    #     else:
    #         raise Exception(f"File upload failed with status code {response.status_code}")

    # def download_file(self, file_url):
    #     # Download a file from the server
    #     response = requests.get(file_url)
    #     if response.status_code == 200:
    #         return response.content
    #     else:
    #         raise Exception(f"File download failed with status code {response.status_code}")

    # # Shouldnt need as only handling signed messages
    # def handle_incoming_message(self, message):
    #     # Process incoming messages based on their type
    #     message = json.loads(message)
        
    #     if message['type'] == 'signed_data':
    #         self.process_signed_message(message)
    #     elif message['type'] == 'client_list':
    #         self.process_client_list(message)
    #     else:
    #         print(f"Received unknown message type: {message['type']}")

    # Handles messages forwarded by the server
    def process_signed_message(self, message, pub_key):
        try:

            # Message sanitisation
            message = json.loads(message)

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
                            # print(f"Error decrypting participant fingerprint: {e}")
                            continue 

                # Return if client isn't intended receiver
                if sender_fingerprint == None:
                    print("Received chat message not intended for this client")
                    return
            elif data['type'] == 'public_chat':
                sender_fingerprint = data['sender']

            # Set default case
            sender_public_key = None
            print("Client:", self.fingerprint)
            print("Sender fingerprint:", sender_fingerprint)
            print("Message:", decrypted_message)


            # ------- TEST DATA -------
            connected_clients = {}

            test_fingerprint = serialization.load_pem_public_key(b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnIRtyWKnSkzKbGWxz5jL\ne/7zmjF360CTsYEtj/3G6W+6vHTxIJLt93eQe8sLGHypACTKHwNQjK8AthK1qyCq\nrYAe+epHV5rp1WNG87NQEDvD1dOcWugA5v77ZsD3Jkw1JZFv/AXCEtUTvv+Mx8Rz\nCthFEf+5g9vINNZuG0ZFZM5bjH8wdXylXa2cyKc9gZEZP+yr+Rh9vjtXR+2c/hwA\nQqanSNFJvf6W8Ij9R0uk+uG3MscFer+AbSknbKengM/yfB4t2Sgmg3w/cJPEJ7OY\nnJbN2LgwncQC3jYwfenniZJ9j9fgCEyVz2Ck88D2FySS/pPh/gIh9lp9KQHuNB9w\nCwIDAQAB\n-----END PUBLIC KEY-----")
            connected_clients[calculate_fingerprint(test_fingerprint)] = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnIRtyWKnSkzKbGWxz5jL\ne/7zmjF360CTsYEtj/3G6W+6vHTxIJLt93eQe8sLGHypACTKHwNQjK8AthK1qyCq\nrYAe+epHV5rp1WNG87NQEDvD1dOcWugA5v77ZsD3Jkw1JZFv/AXCEtUTvv+Mx8Rz\nCthFEf+5g9vINNZuG0ZFZM5bjH8wdXylXa2cyKc9gZEZP+yr+Rh9vjtXR+2c/hwA\nQqanSNFJvf6W8Ij9R0uk+uG3MscFer+AbSknbKengM/yfB4t2Sgmg3w/cJPEJ7OY\nnJbN2LgwncQC3jYwfenniZJ9j9fgCEyVz2Ck88D2FySS/pPh/gIh9lp9KQHuNB9w\nCwIDAQAB\n-----END PUBLIC KEY-----"
            
            test_fingerprint_2 = serialization.load_pem_public_key(b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvSlTreoBmEJuKyL4uqUP\nuUf+nr1cdt3qOWchtLJZmANCwOX0ZT+8Ut0gmzhmwZLaWUv/WANbb4H5e8KbIrQH\nzTk7X13XOCR4jF7zv9EyY/K/9eWIB/gscWZwxVvj00ZBUIqVuq6OAcElhVdQ/kqx\n8IvHAO3rZvnYV/esm+Svr8/NnSYK8n96s0FTM9nUCRr9HSnCSxs9DGd16bGnnx28\nDhUVo3e9MxnPFPKe4DqZ075jn5ngPFjnoJBr0vEEYKd/INqcwPtJ8VNoICFyiLTE\nWTDan+UdqLjcZkxBzVNNEd6Q8SWgwod9rpXfaE5kAluUf3RpV2ffzQ9rbajAaWF0\nxwIDAQAB\n-----END PUBLIC KEY-----")
            connected_clients[calculate_fingerprint(test_fingerprint_2)] = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvSlTreoBmEJuKyL4uqUP\nuUf+nr1cdt3qOWchtLJZmANCwOX0ZT+8Ut0gmzhmwZLaWUv/WANbb4H5e8KbIrQH\nzTk7X13XOCR4jF7zv9EyY/K/9eWIB/gscWZwxVvj00ZBUIqVuq6OAcElhVdQ/kqx\n8IvHAO3rZvnYV/esm+Svr8/NnSYK8n96s0FTM9nUCRr9HSnCSxs9DGd16bGnnx28\nDhUVo3e9MxnPFPKe4DqZ075jn5ngPFjnoJBr0vEEYKd/INqcwPtJ8VNoICFyiLTE\nWTDan+UdqLjcZkxBzVNNEd6Q8SWgwod9rpXfaE5kAluUf3RpV2ffzQ9rbajAaWF0\nxwIDAQAB\n-----END PUBLIC KEY-----"

            connected_clients[sender_fingerprint] = pub_key
            # -------------------------


            # # Search through servers connected clients to find the public key matching the senders fingerprints
            # connected_clients = get_Connected_Clients()

            for client in connected_clients.keys():
                if client == sender_fingerprint:
                    sender_public_key = connected_clients[client]

            # Return if the fingerprint of sender can't be found in connected clients
            if sender_public_key is None:
                print("Received chat message not intended for this client")
                return
            
            # Verify the signature of the message
            if not self.crypto.verify(json.dumps(data).encode() + str(counter).encode(), signature, sender_public_key):
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

            print("-------------------------------------")
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

    # def process_chat_message(self, data):

    #     # Decrypt and process incoming chat messages
    #     try:

    #         # sender_fingerprint, decrypted_message = self.crypto.decrypt_message(self.fingerprint, data)
    #         # chat_content = json.loads(decrypted_message)

    #         # Check if the client was the intended recipient of the message
    #         # if sender_fingerprint != None:
    #         #     return sender_fingerprint, decrypted_message
    #         # else:
    #         return None, None
    #     except Exception as e:
    #         print(f"Error decrypting message: {e}")

    # # Should be a JS function
    # def process_client_list(self, message):
    #     # Process and display the list of connected clients
    #     print("Received client list:")
    #     for server in message['servers']:
    #         print(f"Server: {server['address']}")
    #         for client_key in server['clients']:
    #             print(f"  Client: {self.crypto.calculate_fingerprint()}")

    # # Should be a JS function
    # def run(self):
    #     # Main loop to handle incoming messages
    #     self.connect_to_server()
    #     while True:
    #         try:
    #             message = self.ws.recv()
    #             self.handle_incoming_message(message)
    #         except websocket.WebSocketConnectionClosedException:
    #             print("WebSocket connection closed")
    #             break
    #         except Exception as e:
    #             print(f"Error: {e}")

# Example usage
if __name__ == "__main__":
    client1 = Client("test")
    client2 = Client("test2")
    client3 = Client("test3")

    recipients = {export_public_key(client2.crypto.public_key), export_public_key(client3.crypto.public_key)}

    # Test with multiple servers
    encrypted_message = client1.send_chat_message("Long message wooooo I love long messages", recipients, "localhost")
    client2.process_signed_message(encrypted_message, client1.crypto.public_key)
    client3.process_signed_message(encrypted_message, client1.crypto.public_key)

    # Public chat test
    message = client1.send_public_chat_message("'testing' @#$%*g%&")
    client3.process_signed_message(message, client1.crypto.public_key)

    # Replay attack test
    client1.counter = 0
    encrypted_message = client1.send_chat_message("Replay attack test", recipients, "localhost")
    client2.process_signed_message(encrypted_message, client1.crypto.public_key)
    print("-------------------------------------")

    # Invalid siganture test
    client1.crypto.public_key = "bleh"
    encrypted_message = client1.send_chat_message("Invalid signature test", recipients, "localhost")
    client3.process_signed_message(encrypted_message, client1.crypto.public_key)