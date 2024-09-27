#ifndef SERVER_H
#define SERVER_H

// LOCAL LIBRARIES
#include <string>
#include <vector>
#include <map>
#include "User.h"
#include "Neighbourhood.h" 

// WEBSOCKETS LIBRARIES
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>

class Neighbourhood;
class User;

class Server {
public:

    // constructor and destructor
    Server(const std::string& address, int port);
    ~Server();

    // server control methods
    void startServer();
    void stopServer();
    bool isRunning() const;
    void setNeighbourhood(Neighbourhood* neighbourhood);
    void addConnectedClient(const std::string& fingerprint, User* user);
    void removeConnectedClient(const std::string& fingerprint);
    void onOpen(websocketpp::connection_hdl hdl);
    void onClose(websocketpp::connection_hdl hdl);
    const std::map<std::string, User*>& getConnectedClients() const { return connectedClients; }

    // These methods process different types of incoming messages
    void handleHelloMessage(websocketpp::connection_hdl hdl, const std::string& message);
    void handleChatMessage(websocketpp::connection_hdl hdl, const std::string& message);
    void handlePublicChatMessage(websocketpp::connection_hdl hdl, const std::string& message);
    void handleClientListRequest(websocketpp::connection_hdl hdl);
    void sendClientList();
    void sendClientUpdateRequest(const std::string& serverAddress);
    void Server::sendClientUpdate();
    
    // File transfer methods
    std::string handleFileUpload(const std::string& fileData);
    std::string handleFileRetrieve(const std::string& fileUrl);

    // Encryption methods
    std::string encryptMessage(const std::string& message, const std::string& recipientPublicKey);
    std::string decryptMessage(const std::string& encryptedMessage, const std::string& privateKey);

    // HTTP server methods
    void startHTTPServer();
    void stopHTTPServer();

    // additional methods for Neighbourhood
    std::string getAddress() const;

    // broadcast message to all servers in the neighbourhood
    void broadcastToServers(const std::string& message);

    // some more methods for server info
    std::vector<ServerInfo> gatherClientInfo();

private:

    // server attributes
    std::string address;
    int port;
    std::map<std::string, User*> connectedClients;
    Neighbourhood* neighbourhood;
    websocketpp::server<websocketpp::config::asio> server;
    bool serverRunning;

    // websocket message handling
    void onMessage(websocketpp::connection_hdl hdl, websocketpp::server<websocketpp::config::asio>::message_ptr msg);
    void relayMessage(const std::string& message, const std::string& destinationServer);
    void broadcastToClients(const std::string& message);
    User* findUserByHandle(websocketpp::connection_hdl hdl);

    // client update methods
    void updateConnectedClients(const std::string& fingerprint, bool isConnected);

    // HTTP server
    httplib::Server httpServer; 
    
};

#endif
