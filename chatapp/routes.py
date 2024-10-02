# Ryan Olofsson a1864245, Tyler Chapman 1851834, Kian Esmailzadeh a1851935
from flask import Blueprint, render_template, request, jsonify
from flask_socketio import socketio
from fileSharing import upload_file, retrieve_file
from .serverFunctions import handle_hello, handle_chat, handle_public_chat, handle_client_update_request, handle_client_list_request, handle_server_hello, send_all_clients
from client import Client
from cryptography.hazmat.primitives import serialization 
from crypto import Crypto, export_public_key, calculate_fingerprint
import os

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/api/message', methods=['POST'])
def handle_message():
    print("incomming request:", request.json)
    message = request.json
    message_type = message.get('data', {}).get('type')
    message_type_server = message.get('type')
    # print(server_address)
    if message_type == 'hello':
        return handle_hello(message)
    elif message_type == 'chat':
        return handle_chat(message)
    elif message_type == 'public_chat':
        return handle_public_chat(message)
    elif message_type_server == 'client_update_request':
        return handle_client_update_request()
    elif message_type_server == 'client_list_request':
        return handle_client_list_request()
    elif message_type == 'server_hello':
        return handle_server_hello(message)
    elif message_type_server == 'client_update':
         return jsonify({"status": "Client update received successfully"}), 200 # this wont work because we need to be able to pass in an address as i dont know how to get the address of the server that sent the request in this file
    else:
        return jsonify({"error": "Unknown message type"}), 400

@main.route('/api/upload', methods=['POST'])
def upload():
    server_url = request.form.get('server_url')
    file = request.files.get('file')

    print("server_url:", server_url)
    print("file:", file)

    if not server_url or not file:
        return jsonify({"error": "Missing fields"}), 400
    temp_dir = "./temp"
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    file_path = os.path.join(temp_dir, file.filename).replace("\\", "/")
    print(file_path)
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
        public_key = export_public_key(user_instance.crypto.public_key)
        fingerprint = calculate_fingerprint(user_instance.crypto.public_key)
        return jsonify({"public_key": public_key.decode(), "username": username, "fingerprint": fingerprint}), 200
    else:
        return jsonify({"error": "Username is required"}), 400

@main.route('/api/get_all_clients', methods=['GET'])
def get_all_clients():
    all_clients = send_all_clients()  # Ensure this function returns the current all_clients
    return jsonify(all_clients), 200