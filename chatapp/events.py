from .extensions import socketio

# in this file, add all events to the socketio object

# connection event
@socketio.on('connect')
def handle_connect():
    print('Client connected')

# disconnection event
@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('onJoin')
def handle_on_join(message):
    print(message)