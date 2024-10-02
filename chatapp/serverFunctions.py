import json
import base64
from flask import Flask, request, jsonify
from flask_socketio import emit
from crypto import Crypto, calculate_fingerprint
from fileSharing import upload_file, retrieve_file
from .extensions import socketio
from cryptography.hazmat.primitives import serialization
import requests

app = Flask(__name__)

our_connected_clients = {} # this is the clients that we are connected to

servers_clients = {} # this is the clients of other servers

all_clients = {} # all clients fingerprints including our connected clients and the clients of other servers

Crypto = Crypto()

def handle_hello(message):
    str_public_key = message['data']['public_key']
    public_key = serialization.load_pem_public_key(str_public_key.encode('utf-8'))
    fingerprint = calculate_fingerprint(public_key)
    # print(fingerprint)
    our_connected_clients[fingerprint] = str_public_key
    servers_clients["127.0.0.1:5000"] = list(our_connected_clients.values())
    all_clients[fingerprint] = str_public_key
    socketio.emit('all_clients', all_clients, to='everyone')
    notify_other_servers_of_client_update()
    # print(connected_clients)
    socketio.emit('client_update', create_client_update(our_connected_clients), to='everyone')
    return jsonify({"status": "Hello message recieved", "fingerprint": fingerprint})

def handle_public_chat(message):
    socketio.emit('public_chat', message, to='everyone')
    return jsonify({"status": "Public chat message broadcasted successfully"}), 200
    

def handle_chat(message):
    data = message['data']
    destination_servers = data['destination_servers']
    iv = data['iv']
    symm_keys = data['symm_keys']
    chat_data = data['chat']

    if not all([destination_servers, iv, symm_keys, chat_data]):
        return jsonify({"error": "Missing required fields"}), 400
    
    socketio.emit('chat_message', message, to='everyone')
    return jsonify({"status": "Chat message forwarded successfully"}), 200

def handle_client_list_request(): # not sure if this is right - it is not right. need to know where we track other servers so i can pass that info.
    client_list = create_client_list() 
    socketio.emit('client_list', client_list, to='everyone') # this should be correctish.
    return jsonify({"message": "Client list sent to all clients"}), 200

def handle_client_update_request(): # not sure if this is right 
    client_update = create_client_update(our_connected_clients)
    socketio.emit('client_update', client_update, to='everyone')
    return jsonify({"status": "Client update sent to all servers"}), 200

def remove_connected_client_by_fingerprint(fingerprint):
    # print(connected_clients)
    if fingerprint in our_connected_clients:
        del our_connected_clients[fingerprint]
        notify_other_servers_of_client_update()
        print(f"Client with fingerprint {fingerprint} removed")
    else:
        print(f"Client with fingerprint {fingerprint} not found")
    if fingerprint in all_clients:
        del all_clients[fingerprint]
        print(f"Client with fingerprint {fingerprint} removed from all_clients")
    else:
        print(f"Client with fingerprint {fingerprint} not found in all_clients")

def get_Connected_Clients():
    return all_clients

def handle_server_hello(message):
    server_ip = message['data']['sender']
    client_update_request = {"type": "client_update_request"}
    try:
        response = requests.post(f'http://{server_ip}/api/message', json=client_update_request)
        if response.status_code == 200:
            client_update = response.json()
            servers_clients[server_ip] = client_update['clients']
            client_list = create_client_list()
            socketio.emit('client_list', client_list, to='everyone')
            socketio.emit('all_clients', all_clients, to='everyone')
            print(f"Client update Request sent to {server_ip}")
        else:
            print(f"Failed to send client update Request to {server_ip}")
    except Exception as e:
        print(f"Error sending client update to {server_ip}: {e}")
    return jsonify({"status": "Server hello message recieved"}), 200

# def handle_client_update(message):
#     server_address = request.remote_addr + ":5000" 
#     print(server_address)
#     client_update = message['clients']
#     print(client_update)
#     servers_clients[server_address] = client_update

#     client_list = create_client_list()
#     socketio.emit('client_list', client_list, to='everyone')
#     return jsonify({"status": "Client update recieved"}), 200

def get_server_clients():
    return servers_clients

def create_client_list():
    client_list = {
        "type": "client_list",
        "servers": []
    }
    balls = get_server_clients()
    pog = our_connected_clients
    balls["127.0.0.1:5000"] = list(pog.values())

    for server_address, server_clients in balls.items():
        server_info = {
            "address": server_address,
            "clients": server_clients
        }
        client_list["servers"].append(server_info)
    update_connected_clients_from_server()
    return client_list

def create_client_update(connected_clients):
    clients = list(connected_clients.values())
    client_update = {
        "type": "client_update",
        "clients": clients
    }
    return client_update

# this function notifies other servers of a client update
def notify_other_servers_of_client_update():
    client_update = create_client_update(our_connected_clients)
    for server in servers_clients.keys():
        if server != "127.0.0.1:5000":
            try:
                requests.post(f'http://{server}/api/message', json=client_update)
            except Exception as e:
                print(f"Error sending client update to {server}: {e}")


def update_connected_clients_from_server():
    for server_address, public_keys in servers_clients.items():
        for public_key_string in public_keys:
            public_key = serialization.load_pem_public_key(public_key_string.encode('utf-8'))
            fingerprint = calculate_fingerprint(public_key)
            if fingerprint not in all_clients:
                all_clients[fingerprint] = public_key_string
            else:
                print("client already exists")
    print(all_clients)

def send_all_clients():
    return all_clients