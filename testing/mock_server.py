from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/')
def index():
    return "Mock server is running on 127.0.0.2:80"

@app.route('/api/message', methods=['POST'])
def handle_message():
    message = request.json
    message_type = message.get('type')
    
    if message_type == 'client_update_request':
        print("Received client_update_request")
        client_update = {
            "type": "client_update",
            "clients": [
                "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnIRtyWKnSkzKbGWxz5jL\ne/7zmjF360CTsYEtj/3G6W+6vHTxIJLt93eQe8sLGHypACTKHwNQjK8AthK1qyCq\nrYAe+epHV5rp1WNG87NQEDvD1dOcWugA5v77ZsD3Jkw1JZFv/AXCEtUTvv+Mx8Rz\nCthFEf+5g9vINNZuG0ZFZM5bjH8wdXylXa2cyKc9gZEZP+yr+Rh9vjtXR+2c/hwA\nQqanSNFJvf6W8Ij9R0uk+uG3MscFer+AbSknbKengM/yfB4t2Sgmg3w/cJPEJ7OY\nnJbN2LgwncQC3jYwfenniZJ9j9fgCEyVz2Ck88D2FySS/pPh/gIh9lp9KQHuNB9w\nCwIDAQAB\n-----END PUBLIC KEY-----",
                "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvSlTreoBmEJuKyL4uqUP\nuUf+nr1cdt3qOWchtLJZmANCwOX0ZT+8Ut0gmzhmwZLaWUv/WANbb4H5e8KbIrQH\nzTk7X13XOCR4jF7zv9EyY/K/9eWIB/gscWZwxVvj00ZBUIqVuq6OAcElhVdQ/kqx\n8IvHAO3rZvnYV/esm+Svr8/NnSYK8n96s0FTM9nUCRr9HSnCSxs9DGd16bGnnx28\nDhUVo3e9MxnPFPKe4DqZ075jn5ngPFjnoJBr0vEEYKd/INqcwPtJ8VNoICFyiLTE\nWTDan+UdqLjcZkxBzVNNEd6Q8SWgwod9rpXfaE5kAluUf3RpV2ffzQ9rbajAaWF0\nxwIDAQAB\n-----END PUBLIC KEY-----"
            ]
        }
        client_update_request = {
            "type": "client_update_request"
        }
        response = requests.post('http://127.0.0.1:5000/api/message', json=client_update)
        if response.status_code == 200:
            print("Client update sent to 127.0.0.1:5000")
        else:
            print("Failed to send client update request to 127.0.0.1:5000")
        return jsonify(client_update)
    
    elif message_type == 'client_update':
        print("Received client_update")
        return jsonify({"status": "Client update recieved"}), 200
    else:
        return jsonify({"error": "Unknown message type"}), 400

if __name__ == '__main__':
    app.run(host='127.0.0.2', port=80)