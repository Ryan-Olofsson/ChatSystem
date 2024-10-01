import json
import base64
import requests
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
        self.connect_to_server("http://127.0.0.1:5000")  # Replace with your server address

    def connect_to_server(self, server_address):
        self.sio.connect(server_address)  # Connect to the server
        print(f"Connected to server at {server_address}")

    # Could be a JS function, may need to be a signed message
    def send_hello(self):
        # Send initial hello message to establish connection and share public key
        hello_message = self.create_signed_message({
            "type": "hello",
            "public_key": export_public_key(self.crypto.public_key).decode()
        })
        socketio.emit('signed_data_hello', hello_message)

    def create_signed_message(self, data):
        # Create a signed message with counter to prevent replay attacks
        message = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter
        }
        signature = self.crypto.sign(json.dumps(data) + str(self.counter))
        message["signature"] = base64.b64encode(signature).decode()

        self.counter += 1
        return message

    # Need to be modified to handle recipient as just a public key
    def send_chat_message(self, message, recipients, destination_servers):
        # Encrypt and send a chat message to specified recipients
        chat_content = {
            "participants": [],
            "message": message
        }

        chat_data = {
            "type": "chat",

            # Assumes destination servers and recipients are in a matching ordered list
            "destination_servers": destination_servers,
            "symm_keys": [],
            "iv": None,
            "chat": chat_content
        }


        # Set variable for initialising the iv and symm_key
        first = True

        # Encrypt message and get encrypted symmetric key for each recipient
        for recipient in recipients:
            recipient_public_key = serialization.load_pem_public_key(recipient)

            if first:
                encrypted_data = self.crypto.encrypt_message(message, recipient_public_key)
                chat_data["iv"] = encrypted_data["iv"]
                chat_data["symm_keys"].append(encrypted_data["symm_key"])
                first = False
            else:
                # Need to change code so that the sym_key is being used for asymmetric_encrypt not base64.b64encode(encrypted_sym_key).decode() which is being passed
                sym_key_bytes = base64.b64decode(chat_data["symm_keys"][0])  # Decode from base64 to bytes
                encrypted_sym_key = self.crypto.asymmetric_encrypt(sym_key_bytes, recipient_public_key)
                chat_data["symm_keys"].append(base64.b64encode(encrypted_sym_key).decode())


        chat_content["message"] = self.crypto.group_symmetric_encrypt(chat_content["message"], chat_data["symm_keys"][0], chat_data["iv"])
        chat_content["participants"].append(self.crypto.group_symmetric_encrypt(self.fingerprint, chat_data["symm_keys"][0], chat_data["iv"]))

        for recipient in recipients:
            chat_content["participants"].append(self.crypto.group_symmetric_encrypt(calculate_fingerprint(recipient_public_key), chat_data["symm_keys"][0], chat_data["iv"]))

        

        chat_data = self.create_signed_message(chat_data)
        socketio.emit('signed_data_chat', chat_data)

    def send_public_chat_message(self, message):
        # Send a public chat message visible to all clients
        public_chat_message = self.create_signed_message({
            "type": "public_chat",
            "sender": self.fingerprint,
            "message": message
        })

        socketio.emit('signed_data_public', public_chat_message)

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

    def process_signed_message(self, message):
        # Verify the signature and counter of incoming signed messages
        if message['type'] != 'signed_data':
            print(f"Received unknown message type: {message['type']}")
            return

        # Get message data
        data = message['data']
        counter = message['counter']
        signature = base64.b64decode(message['signature'])
        sender_fingerprint = None

        # Get fingerprint of sender if the client is the intended reciever, different methods depending on data type
        if data['type'] == 'chat':
            sender_fingerprint, decrypted_message = self.process_chat_message(data, sender_public_key)

            # Return if client isn't intended receiver
            if sender_fingerprint == None:
                print("Received chat message not intended for this client")
                return
        elif data['type'] == 'public_chat':
            sender_fingerprint = data['sender']

        # Set default case
        sender_public_key = None

        # Search through servers connected clients to find the public key matching the senders fingerprints
        connected_clients = get_Connected_Clients()
        for client in connected_clients:
            if client['fingerprint'] == sender_fingerprint:
                sender_public_key = client['public_key']

        # Return if the fingerprint of sender can't be found in connected clients
        if sender_public_key is None:
            print("Received chat message not intended for this client")
            return
        
        # Verify the signature of the message
        if not self.crypto.verify(json.dumps(data).encode() + str(counter).encode(), signature, sender_public_key):
            print("Invalid signature")
            return
        
        # Verify the counter of the message
        if not self.verify_counter(sender_fingerprint, counter):
            print("Invalid counter value, possible replay attack")
            return
        
        # Print the message if the client is intended recipient, signature is verified and the counter is verified
        if data['type'] == 'public_chat':
            print(f"Received public chat message: {data['message']}")
        
        if data['type'] == 'chat':
            print(f"Received chat message from {sender_fingerprint}: {decrypted_message}")

    def verify_counter(self, counter, sender_fingerprint):
        # Verify that the message counter is greater than the last received counter
        last_counter = self.received_counters.get(sender_fingerprint)
        if counter > last_counter:
            self.received_counters[sender_fingerprint] = counter
            return True
        return False

    def process_chat_message(self, data):
        # Decrypt and process incoming chat messages
        try:
            sender_fingerprint, decrypted_message = self.crypto.decrypt_message(data, self.fingerprint)
            # chat_content = json.loads(decrypted_message)

            # Check if the client was the intended recipient of the message
            if sender_fingerprint != None:
                return sender_fingerprint, decrypted_message
            else:
                return None, None
        except Exception as e:
            print(f"Error decrypting message: {e}")

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

    client1.send_chat_message("Testing", recipients, "localhost")