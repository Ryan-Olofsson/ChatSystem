# Ryan Olofsson a1864245, Tyler Chapman 1851834, Kian Esmailzadeh a1851935

from flask_socketio import emit
from flask import request

from .extensions import socketio
from crypto import Crypto, calculate_fingerprint, export_public_key
from .serverFunctions import remove_connected_client_by_fingerprint, send_all_clients, send_our_clients, send_our_connected_clients
from cryptography.hazmat.primitives import serialization
import requests
import json
from client import Client


# in this file, add all events to the socketio object
connected_users = {}
Crypto = Crypto()

# connection event
@socketio.on("connect")
def handle_connect():
    print("server websocket connected")

# disconnection event
@socketio.on("disconnect")
def handle_disconnect():
    # print("Client disconnected")
    username = next((user for user, info in connected_users.items() if info['sid'] == request.sid), None)
    if username:
        fingerprint = connected_users[username]['fingerprint']
        del connected_users[username]
        print(f"{username} disconnected")
        # print(connected_users)
        remove_connected_client_by_fingerprint(fingerprint)


@socketio.on("onJoin")
def handle_on_join(message):
    print(message)

@socketio.on("sendMessage")
def handle_send_message(message):
    print(message)
    # Broadcast the message to all clients
    emit("chat", {"message": message}, broadcast=True) 


@socketio.on("addUser")
def handle_add_user(message):
    username = message.get('username')
    print(username)
    if isinstance(username, str) and username:  # Check if username is a valid string
        str_public_key = message.get('public_key')
        # print(str_public_key)
        public_key = serialization.load_pem_public_key(str_public_key.encode('utf-8'))
        fingerprint = calculate_fingerprint(public_key)
        connected_users[username] = {
            "sid": request.sid,
            "fingerprint": fingerprint,
            "public_key": str_public_key
        }
        # print(connected_users)
    print(f"{username} connected with sid {request.sid}")
    # print(connected_users)

@socketio.on("signed_data_chat")
def handle_signed_data_chat(message):
    data = message['data']
    destination_servers = data['destination_servers']

    for server in destination_servers:
        try:
            response = requests.post(f'http://{server}/api/message', json=message)
            if response.status_code == 200:
                print(f"Message sent to {server}")
            else:
                print(f"Failed to send message to {server}")
        except Exception as e:
            print(f"Error sending message to {server}: {e}")

@socketio.on("private_chat")
def handle_private_chat(data):
    message = data.get("message")
    recipient = data.get("to")
    sender = data.get("from")

    try: 
        our_clients = send_our_clients()
        user_instance = our_clients.get(sender)

        all_clients = send_all_clients()
        recipient_pub_key = all_clients.get(recipient)

        public_key = serialization.load_pem_public_key(recipient_pub_key.encode('utf-8'))
        public_key = export_public_key(public_key)
        recipients = {public_key}

        if user_instance:
            print("user instance found: ", user_instance.fingerprint)

            signed_message = user_instance.send_chat_message(message, recipients, ["127.0.0.1:5000"])
            handle_signed_data_chat(signed_message)
        else:
            print(f"No client instance found for sender: {sender}")

    except Exception as e:
        print(f"Failed to handle private message")

@socketio.on("group_chat")
def handle_group_chat(data):
    message = data.get("message")
    recipients = data.get("recipients")
    sender = data.get("from")

    public_keys = []

    try: 
        our_clients = send_our_clients()
        user_instance = our_clients.get(sender)

        all_clients = send_all_clients()
        for recipient in recipients:
            recipient_pub_key = all_clients.get(recipient)
            public_key = serialization.load_pem_public_key(recipient_pub_key.encode('utf-8'))
            public_keys.append(export_public_key(public_key))

        if user_instance:
            print("user instance found: ", user_instance.fingerprint)

            signed_message = user_instance.send_chat_message(message, public_keys, ["127.0.0.1:5000"])
            handle_signed_data_chat(signed_message)
        else:
            print(f"No client instance found")

    except Exception as e:
        print(f"Failed to handle private message")
