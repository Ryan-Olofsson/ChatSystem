import json
import base64
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from crypto import calculate_fingerprint

app = Flask(__name__)

connected_clients = []

@app.route('/api/message', methods=['POST'])
def handle_message():
    message = request.json
    message_type = message.get('type')

    if message_type == 'hello':
        return handle_hello(message)
    elif message_type == 'chat':
        return handle_chat(message)
    elif message_type == 'public_chat':
        return handle_public_chat(message)
    elif message_type == 'client_update_request':
        return handle_client_update_request(message)
    elif message_type == 'client_list_request':
        return handle_client_list_request(message)
    else:
        return jsonify({"error": "Unknown message type"}), 400

def handle_hello(message):
    public_key = message['data']['public_key']
    fingerprint = calculate_fingerprint(public_key)
    connected_clients[fingerprint] = public_key
    return jsonify({"status": "Hello message recieved", "fingerprint": fingerprint})

def handle_public_chat(message):
    sender = message['data']['sender']
    chat_message = message['data']['message']
    SocketIO.emit('public_chat', {'sender': sender, 'message': chat_message}, broadcast=True)
    return jsonify({"status": "Public chat message broadcasted successfully"}), 200
    

def handle_chat(message):
    data = message['data']
    destination_servers = data['destination_servers']
    iv = data['iv']
    symm_keys = data['symm_keys']
    chat_data = data['chat']

    if not all([destination_servers, iv, symm_keys, chat_data]):
        return jsonify({"error": "Missing required fields"}), 400

    SocketIO.emit('chat_message', {
        'destination_servers': destination_servers,
        'iv': iv,
        'symm_keys': symm_keys,
        'chat': chat_data
    }, broadcast=True)
    return jsonify({"status": "Chat message forwarded successfully"}), 200

def handle_client_list_request(message): # not sure if this is right
    client_list = create_client_list(connected_clients)
    return jsonify(client_list), 200

def handle_client_update_request(message): # not sure if this is right 
    client_update = create_client_update(connected_clients)
    SocketIO.emit('client_update', client_update, broadcast=True)
    return jsonify({"status": "Client update sent to all servers"}), 200

def create_client_list(servers): # not sure if this is right
    client_list = {
        "type": "client_list",
        "servers": []
    }
    
    for server in servers:
        server_info = {
            "address": server.address,
            "clients": [client for client in server.clients]
        }
        client_list["servers"].append(server_info)
    
    return client_list

def create_client_update(clients): # not sure if this is right
    return {
        "type": "client_update",
        "clients": list(clients.values())
    }
