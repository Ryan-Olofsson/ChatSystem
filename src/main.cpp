// Olaf's Neighbourhood Protocol: 

// Main components:
// • Users: Have key pairs, connect to one server at a time
// • Servers: Receive and relay messages, form a meshed network (neighbourhood)
// • Neighbourhood: Servers are aware of and connect to all other servers
// • Fingerprint: Unique user ID (SHA-256 hash of RSA public key)

// Network topology:
// • Client (Sender) -> Server (Sender's) -> Server (Receiver's) -> Client (Receiver)
// • Uses WebSockets (RFC 6455) for transport layer
// • Clients can only connect to users on their home server or directly connected servers

// Message structure:
// • UTF-8 JSON objects
// • Signed messages with counter to prevent replay attacks
// • Encrypted using asymmetric (RSA) and symmetric (AES) encryption

// Server responsibilities:
// • Relay messages, minimal parsing and state storage
// • Maintain client list, files, and list of other servers in neighbourhood
// • Check message format to avoid forwarding garbage
// • Located by address (optionally including port)

// Encryption details:
// • Asymmetric: RSA (2048-bit key, OAEP padding, SHA-256)
// • Symmetric: AES (GCM mode, 128-bit key)
// • Signing: RSA-PSS (SHA-256, 32-byte salt)

// Message flow:
// 1. Create message
// 2. Apply signature (RSA-PSS)
// 3. Encrypt message (AES)
// 4. Encrypt AES key with recipient's public key (RSA)
// 5. Format for sending

// Neighbourhood management:
// • New servers added manually by admin agreement
// • Inconsistent neighbourhood lists may cause communication issues

#include <iostream>
#include <string>
#include <vector>
#include <map>

// OPENSSL LIBRARIES
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// WEBSOCKETS LIBRARIES
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>

// LOCAL LIBRARIES
#include "include/User.h"
#include "include/Server.h"
#include "include/Neighbourhood.h"

int main() {
    Neighbourhood neighbourhood;
    
    Server server1("localhost", 8080);
    Server server2("localhost", 8081);
    
    neighbourhood.addServer(&server1);
    neighbourhood.addServer(&server2);
    
    User alice("Alice");
    User bob("Bob");
    

    /* EXAMPLE USAGE OF THE PROTOCOL 
    
    // start the servers
    server1.start();
    server2.start();

    // implement client connections
    server1.addConnectedClient(alice.getFingerprint(), &alice);
    server2.addConnectedClient(bob.getFingerprint(), &bob);

    // implement message sending and receiving logic
    std::string message = "Hello, Bob!";
    std::string encryptedMessage = alice.encryptMessage(message, bob.getPublicKey());
    std::string signature = alice.signMessage(message);

    // simulate sending the message from alice to bob
    server1.relayMessage(encryptedMessage + ":" + signature, "localhost:8081");

    // in a real scenario, server2 would receive this message and pass it to bob
    // bob would then decrypt and verify the message
    std::string receivedMessage = bob.decryptMessage(encryptedMessage);
    bool isVerified = bob.verifySignature(receivedMessage, signature, alice.getPublicKey());

    std::cout << "Bob received: " << receivedMessage << std::endl;
    std::cout << "Signature verified: " << (isVerified ? "Yes" : "No") << std::endl;

    // stop the servers
    server1.stop();
    server2.stop();
    
    */
    
    
    return 0;
}
