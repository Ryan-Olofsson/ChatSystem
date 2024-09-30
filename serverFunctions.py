import json
import base64
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from crypto import calculate_fingerprint
from pyjson import create_client_list, create_client_update
from fileSharing import upload_file, retrieve_file

app = Flask(__name__)

connected_clients = []

def is_valid_iv(iv):
    return isinstance(iv, str) and len(iv) == 16 and all(c in '0123456789abcdef' for c in iv) # unsure if this will work

def is_valid_symmetric_key(key):
    return isinstance(key, str) and len(key) in [16, 24, 32]  # Example lengths for AES unsure if these will work

def is_valid_chat_data(chat_data):
    return isinstance(chat_data, str) and len(chat_data) > 0  # Ensure it's a non-empty string, unsure if this will work


def handle_hello(message):
    public_key = message['data']['public_key']
    fingerprint = calculate_fingerprint(public_key)
    connected_clients[fingerprint] = public_key
    SocketIO.emit('client_update', create_client_update(connected_clients), broadcast=True)
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
    
    if not all([is_valid_iv(iv), is_valid_symmetric_key(symm_keys), is_valid_chat_data(chat_data)]):
        return jsonify({"error": "Invalid"}), 400

    SocketIO.emit('chat_message', {
        'destination_servers': destination_servers,
        'iv': iv,
        'symm_keys': symm_keys,
        'chat': chat_data
    }, broadcast=True)
    return jsonify({"status": "Chat message forwarded successfully"}), 200

def handle_client_list_request(): # not sure if this is right - it is not right. need to know where we track other servers so i can pass that info.
    client_list = create_client_list(connected_clients) # need to pass servers instead - cant do currently
    SocketIO.emit('client_list', client_list, broadcast=True) # this should be correctish.
    return jsonify({"message": "Client list sent to all clients"}), 200

def handle_client_update_request(): # not sure if this is right 
    client_update = create_client_update(connected_clients)
    SocketIO.emit('client_update', client_update, broadcast=True)
    return jsonify({"status": "Client update sent to all servers"}), 200