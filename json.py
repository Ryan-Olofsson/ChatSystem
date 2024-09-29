import json as js
import base64

m_counter = 0

class ClientMessageStructure:
    def __init__(self, message_type, data, counter, signature):
        self.type = message_type
        self.data = data
        self.counter = counter
        self.signature = signature

class ClientHelloData:
    def __init__(self, public_key):
        self.type = "hello"
        self.public_key = public_key

class ServerInfo:
    def __init__(self, address, clients):
        self.address = address
        self.clients = clients

class ClientList:
    def __init__(self, servers):
        self.type = "client_list"
        self.servers = servers

def create_signed_message(data):
    global m_counter
    message = {
        "type": "signed_data",
        "data": data,
        "counter": m_counter
    }

    message_str = js.dumps(data)
    signature_input = message_str + str(m_counter)
    signature = base64.b64encode(signature_input.encode()).decode

    message["signature"] = signature
    m_counter += 1
    return message

def hello_message(public_key):
    hello_data = ClientHelloData(public_key)
    return create_signed_message(hello_data.__dict__)

def create_chat_message(destinations, iv, symm_keys, inner_chat):
    chat_data = {
        "type": "chat",
        "destinations": destinations,
        "iv": iv,
        "symm_keys": symm_keys,
        "chat": inner_chat
    }
    return create_signed_message(chat_data)

def inner_chat_message(participants_signatures, message):
    chat_inner = {
        "participants": [encode_fingerprint(participant) for participant in participants_signatures],
        "message": message
    }
    return chat_inner

def encode_fingerprint(fingerprint):
    return base64.b64encode(fingerprint.encode()).decode()

def public_chat(fingerprint, message):
    public_chat_data = {
        "type": "public_chat",
        "sender": encode_fingerprint(fingerprint),
        "message": message
    }
    return create_signed_message(public_chat_data)

def create_client_list(servers):
    client_list = {
        "type": "client_list",
        "servers": []
    }
    
    for server in servers:
        server_info = {
            "address": server.address,
            "clients": server.clients
        }
        client_list["servers"].append(server_info)
    
    return client_list

def create_client_update(clients):
    client_update = {
        "type": "client_update",
        "clients": clients
    }
    return client_update

def create_client_update_request():
    return {"type": "client_update_request"}