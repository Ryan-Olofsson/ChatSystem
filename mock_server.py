from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/api/message', methods=['POST'])
def handle_message():
    message = request.json
    message_type = message.get('type')
    
    if message_type == 'client_update_request':
        print("Received client_update_request")
        client_update = {
            "type": "client_update",
            "clients": [
                "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7Q3+5Q==\n-----END PUBLIC KEY-----",
                "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7Q3+5Q==\n-----END PUBLIC KEY-----"
            ]
        }
        client_update_request = {
            "type": "client_update_request"
        }
        response = requests.post('http://127.0.0.1:5000/api/message', json=client_update_request)
        if response.status_code == 200:
            print("Client update request sent to 127.0.0.1:5000")
        else:
            print("Failed to send client update request to 127.0.0.1:5000")
        return jsonify(client_update)
    else:
        return jsonify({"error": "Unknown message type"}), 400

if __name__ == '__main__':
    app.run(host='127.0.0.2', port=5000)