from flask import Blueprint, render_template, request, jsonify
from flask_socketio import socketio
from pyjson import create_client_list, create_client_update
from fileSharing import upload_file, retrieve_file
from .serverFunctions import handle_hello, handle_chat, handle_public_chat, handle_client_update_request, handle_client_list_request
from client import Client
from cryptography.hazmat.primitives import serialization 

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/api/message', methods=['POST'])
def handle_message():
    print("incomming request:", request.json)
    message = request.json
    message_type = message['data'].get('type')
    if message_type == 'hello':
        return handle_hello(message)
    elif message_type == 'chat':
        return handle_chat(message)
    elif message_type == 'public_chat':
        return handle_public_chat(message)
    elif message_type == 'client_update_request':
        return handle_client_update_request(message)
    elif message_type == 'client_list_request':
        return handle_client_list_request()
    else:
        return jsonify({"error": "Unknown message type"}), 400


@main.route('/api/upload', methods=['POST'])
def upload():
    server_url = request.form.get('server_url')
    file = request.files['file']

    if not server_url or not file:
        return jsonify({"error": "Missing fields"}), 400
    file_path = f"./temp/{file.filename}"
    file.save(file_path)
    
    file_url = upload_file(server_url, file_path)

    if file_url:
        return jsonify({"file_url": file_url}), 200
    else:
        return jsonify({"error": "Failed to upload file"}), 500
    
@main.route('/api/download', methods=['GET'])
def download():
    file_url = request.args.get('file_url')
    download_path = request.args.get('download_path', 'downloaded_file')

    if not file_url:
        return jsonify({"error": "Missing fields"}), 400
    
    try:
        retrieve_file(file_url, download_path)
        return jsonify({"status": "File downloaded successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/initialize_user', methods=['POST'])
def initialize_user():
    username = request.json.get('username')
    if username:
        user_instance = Client(username)
        public_key = user_instance.crypto.export_public_key().decode('utf-8')  # Assuming this method exists
        return jsonify({"public_key": public_key, "username": username}), 200
    else:
        return jsonify({"error": "Username is required"}), 400
