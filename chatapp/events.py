from flask_socketio import emit
from flask import request

from .extensions import socketio

# in this file, add all events to the socketio object
connected_users = {}
# connection event
@socketio.on("connect")
def handle_connect():
    username = request.json.get('username')
    connected_users[username] = request.sid
    print(f"{username} connected")

# disconnection event
@socketio.on("disconnect")
def handle_disconnect():
    username = next((user for user, sid in connected_users.items() if sid == request.sid), None)
    if username:
        del connected_users[username]
        print(f"{username} disconnected")

@socketio.on("onJoin")
def handle_on_join(message):
    print(message)

@socketio.on("sendMessage")
def handle_send_message(message):
    print(message)
    # Broadcast the message to all clients
    emit("chat", {"message": message}, broadcast=True) 

#@SocketIO.on('disconnect')
#def handle_disconnect():
    # need a way to identify fingerprint of client that disconnected., storing it somewhere for use
    #fingerprint = x
    # if fingerprint in connected_clients:
        # del connected_clients[fingerprint]
        #SocketIO.emit('client_update', create_client_update(connected_clients), broadcast=True)
    #return jsonify({"status": "Client disconnected"}), 200 #remove this once disconnection logic works.


