import json
import base64
import websocket
import requests
from crypto import Crypto



# WBESOCKET LOGIC IS PURELY FOR PLACEHOLDER PURPOSES



class Client:
    # Server address is useless rn
    def __init__(self, username):
        self.server_address = None
        self.username = username
        self.crypto = Crypto()
        self.fingerprint = self.crypto.calculate_fingerprint()
        self.counter = 0
        self.ws = None
        self.received_counters = {}  # To track counters for each sender

    # Could be a JS function
    def connect_to_server(self):
        # Establish WebSocket connection to the server
        self.ws = websocket.create_connection(f"ws://{self.server_address}")
        self.send_hello()

    # Could be a JS function, may need to be a signed message
    def send_hello(self):
        # Send initial hello message to establish connection and share public key
        hello_message = self.create_signed_message({
            "type": "hello",
            "public_key": self.crypto.export_public_key().decode()
        })
        self.ws.send(json.dumps(hello_message))

    # Could be a JS function
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

    # May need to be modified to handle recipient as just a public key
    def send_chat_message(self, message, recipients, destination_servers):
        # Encrypt and send a chat message to specified recipients
        chat_data = ({
            "type": "chat",
            "destination_servers": destination_servers,
            "symm_keys": [],
            "chat": chat_content
        })

        chat_content = {
            "participants": [self.fingerprint] + [recipient.fingerprint for recipient in recipients],
            "message": message
        }
        
        # Need to figure out how to handle signature and tag, signature may be handled in the signed chat process not encryption
        first = True

        # Encrypt message and get encrypted symmetric key for each recipient
        for recipient in recipients:
            if first:
                encrypted_data = self.crypto.encrypt_message(message, recipient.crypto.public_key)
                chat_data["iv"] = encrypted_data["iv"]
                chat_data["symm_keys"].append(encrypted_data["symm_key"])
                first = False
            else:
                chat_data["symm_keys"].append(base64.b64encode(self.crypto.asymmetric_encrypt(chat_data["symm_keys"][0], recipient.crypto.public_key)).decode())

        chat_content["participants"] = self.crypto.group_symmetric_encrypt(chat_content["participants"], chat_data["symm_keys"][0], chat_data["iv"])
        chat_content["message"] = self.crypto.group_symmetric_encrypt(chat_content["message"], chat_data["symm_keys"][0], chat_data["iv"])

        chat_data = self.create_signed_message(chat_data)
        self.ws.send(json.dumps(chat_data))

    # Could be a JS function, may need to be a signed message
    def send_public_chat_message(self, message):
        # Send a public chat message visible to all clients
        public_chat_message = self.create_signed_message({
            "type": "public_chat",
            "sender": self.fingerprint,
            "message": message
        })

        self.ws.send(json.dumps(public_chat_message))

    # # Should be a JS function
    # def request_client_list(self):
    #     # Request the list of connected clients from the server
    #     request = {
    #         "type": "client_list_request"
    #     }
    #     self.ws.send(json.dumps(request))

    def upload_file(self, file_path):
        # Upload a file to the server
        with open(file_path, 'rb') as file:
            response = requests.post(f"http://{self.server_address}/api/upload", files={'file': file})
        if response.status_code == 200:
            return response.json()['file_url']
        else:
            raise Exception(f"File upload failed with status code {response.status_code}")

    def download_file(self, file_url):
        # Download a file from the server
        response = requests.get(file_url)
        if response.status_code == 200:
            return response.content
        else:
            raise Exception(f"File download failed with status code {response.status_code}")

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

        sender_public_key = self.get_public_key_for_sender(message)  # You need to implement this method
        data = message['data']
        counter = message['counter']
        signature = base64.b64decode(message['signature'])

        if not self.verify_counter(sender_public_key, counter):
            print("Invalid counter value, possible replay attack")
            return

        if not self.crypto.verify(json.dumps(data).encode() + str(counter).encode(), signature, sender_public_key):
            print("Invalid signature")
            return

        if data['type'] == 'chat':
            self.process_chat_message(data, sender_public_key)
        elif data['type'] == 'public_chat':
            self.process_public_chat_message(data)

    def verify_counter(self, sender_public_key, counter):
        # Verify that the message counter is greater than the last received counter
        sender_fingerprint = self.crypto.calculate_fingerprint()
        last_counter = self.received_counters.get(sender_fingerprint, -1)
        if counter > last_counter:
            self.received_counters[sender_fingerprint] = counter
            return True
        return False

    def process_chat_message(self, data, sender_public_key):
        # Decrypt and process incoming chat messages
        try:
            decrypted_message = self.crypto.decrypt_message(data, sender_public_key)
            chat_content = json.loads(decrypted_message)
            if self.fingerprint in chat_content['participants']:
                print(f"Received chat message: {chat_content['message']}")
            else:
                print("Received chat message not intended for this client")
        except Exception as e:
            print(f"Error decrypting message: {e}")

    def process_public_chat_message(self, data):
        # Process incoming public chat messages
        print(f"Received public chat message from {data['sender']}: {data['message']}")

    # # Should be a JS function
    # def process_client_list(self, message):
    #     # Process and display the list of connected clients
    #     print("Received client list:")
    #     for server in message['servers']:
    #         print(f"Server: {server['address']}")
    #         for client_key in server['clients']:
    #             print(f"  Client: {self.crypto.calculate_fingerprint()}")

    # Should be a JS function
    def run(self):
        # Main loop to handle incoming messages
        self.connect_to_server()
        while True:
            try:
                message = self.ws.recv()
                self.handle_incoming_message(message)
            except websocket.WebSocketConnectionClosedException:
                print("WebSocket connection closed")
                break
            except Exception as e:
                print(f"Error: {e}")

# Example usage
if __name__ == "__main__":
    client = Client("test")
    client.run()