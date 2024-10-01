from flask_socketio import emit
from flask import request

from .extensions import socketio
from crypto import Crypto
from .serverFunctions import remove_connected_client_by_fingerprint
# in this file, add all events to the socketio object
connected_users = {}
Crypto = Crypto()
# connection event
@socketio.on("connect")
def handle_connect():
    print("Client connected")

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
        fingerprint = Crypto.calculate_fingerprint()
        public_key = message.get('public_key')
        connected_users[username] = {
            "sid": request.sid,
            "fingerprint": fingerprint,
            "public_key": public_key
        }
        print(connected_users)
    print(f"{username} connected with sid {request.sid}")
    # print(connected_users)


#@SocketIO.on('disconnect')
#def handle_disconnect():
    # need a way to identify fingerprint of client that disconnected., storing it somewhere for use
    #fingerprint = x
    # if fingerprint in connected_clients:
        # del connected_clients[fingerprint]
        #SocketIO.emit('client_update', create_client_update(connected_clients), broadcast=True)
    #return jsonify({"status": "Client disconnected"}), 200 #remove this once disconnection logic works.


