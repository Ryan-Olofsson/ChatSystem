#include "Server.h"
#include <iostream>
#include "include/User.h"
#include "include/Neighbourhood.h"
#include <njson.hpp>
#include <httplib.h>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <jsonfunctions.hpp>

using namespace std;
using json = nlohmann::json;

// server constructor
Server::Server(const std::string& address, int port) : address(address), port(port), neighbourhood(nullptr) {
    
    // initialise server
    server.init_asio(); // asio server init
    server.set_message_handler(bind(&Server::onMessage, this, std::placeholders::_1, std::placeholders::_2)); // set message handler
    server.set_open_handler(bind(&Server::onOpen, this, std::placeholders::_1)); // set open handler
    server.set_close_handler(bind(&Server::onClose, this, std::placeholders::_1)); // set close handler

    // set up server endpoint
    server.set_reuse_addr(true); // allow server to reuse address
    server.listen(port); // listen on specified port
    server.start_accept(); // start accepting incoming connections

    std::cout << "Server initialised on " << address << ":" << port << std::endl;

}

// server destructor
Server::~Server() {

    /* this is for when the server is destroyed. */

    // stop server if running
    stopServer();

    // clean up connected clients
    for (auto& client : connectedClients) {
        delete client.second; 
    }
    connectedClients.clear();

    // clean up the neighbourhood if it exists
    if (neighbourhood) {
        delete neighbourhood;
        neighbourhood = nullptr;
    }

    std::cout << "server cleaned up and destroyed." << std::endl;

}

void Server::startServer() {

    /* attempt to start the server */

    try {
        // start asio server
        server.run();
        std::cout << "Server started successfully on " << address << ":" << port << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "Unknown error occurred while starting the server" << std::endl;
    }
    
}

void Server::stopServer() {

    /* this'll stop the server */

    if (isRunning()) {

        // stop accepting new connections
        server.stop_listening();

        // close all existing connections
        server.stop_perpetual(); // stop_perpetual() is a websocketpp method
        server.stop(); // stop() is a websocketpp method

        // stop asio io_service
        server.get_io_service().stop();

        // set flag indicating the server has been stopped
        serverRunning = false;

        std::cout << "Server has been stopped." << std::endl;
        
    } else {
        std::cout << "Server is not running. No action needed." << std::endl;
    }

}

bool Server::isRunning() const {

    /* this checks if the server is running */
    return server.is_listening(); // is_listening() is a websocketpp method

}

void Server::setNeighbourhood(Neighbourhood* neighbourhood) {

    // set the neighbourhood
    this->neighbourhood = neighbourhood;

}

// The original code did not check if the user is already connected before adding them to the connected clients map.
// This could lead to unexpected behavior if a user is already connected and their connection is overwritten.
// To fix this, we will add a check to ensure the user is not already connected before adding them to the map.

void Server::addConnectedClient(const std::string& fingerprint, User* user) {

    // the original code doesnt check if the user is already 
    // connected before adding them to the connected clients map.
    // this could cause overwriting of existing connections.
    // connectedClients[fingerprint] = user;

    // adding a check to prevent overwriting existing connections
    if (connectedClients.find(fingerprint) == connectedClients.end()) {
        connectedClients[fingerprint] = user;
    } else {
        std::cerr << "User with fingerprint " << fingerprint << " is already connected." << std::endl;
    }

}

void Server::removeConnectedClient(const std::string& fingerprint) {
    auto it = connectedClients.find(fingerprint);
    if (it != connectedClients.end()) {
        delete it->second;
        connectedClients.erase(it);
    }
    // remove a connected client
}

void Server::onOpen(websocketpp::connection_hdl hdl) {

    // this'll handle the connection open
    // e.g. add the client to connectedClients
    // and log the connection
    User* user = findUserByHandle(hdl); // find the user associated with the handle
    if (user) { // if the user is found
        addConnectedClient(user->getFingerprint(), user); // add the user to the connected clients
        std::cout << "New connection opened for user: " << user->getFingerprint() << std::endl; // log the connection
    } else {
        std::cout << "Failed to find user for handle: " << hdl.lock().get() << std::endl; // log the failure to find user
    }

}   

void Server::onClose(websocketpp::connection_hdl hdl) {

    // this'll handle the connection closure
    // e.g. remove the client from connectedClients
    // and log the disconnection
    
    User* user = findUserByHandle(hdl); // find the user associated with the handle
    if (user) { // if the user is found
        removeConnectedClient(user->getFingerprint()); // remove the user from the connected clients
        std::cout << "Connection closed for user: " << user->getFingerprint() << std::endl; // log the disconnection
    } else {
        std::cout << "Failed to find user for handle: " << hdl.lock().get() << std::endl; // log the failure to find user
    }
}

void Server::onMessage(websocketpp::connection_hdl hdl, websocketpp::server<websocketpp::config::asio>::message_ptr msg) {

    // handle incoming messages

}

void Server::relayMessage(const std::string& message, const std::string& destinationServer) {

    // relay message to another server

}

void Server::broadcastToClients(const std::string& message) {

    // broadcast message to all connected clients
    for (const auto& client : connectedClients) {
        client.second->sendMessage(message);
    }
}

User* Server::findUserByHandle(websocketpp::connection_hdl hdl) {    // find and return the User associated with the given connection handle
    for (const auto& client : connectedClients) { // iterate through connected clients
        if (!client.second->getHandle().owner_before(hdl) && !hdl.owner_before(client.second->getHandle())) { // if the handle is the same as the one passed in
            return client.second; // return the user
        }
    }
    return nullptr;
}


/* FYI i added new methods to handle different types of messages and requests */

void Server::handleHelloMessage(websocketpp::connection_hdl hdl, const std::string& message) {
    // todo: implement hello message handling
    json msg = json::parse(message); // parse the message
    string publicKey = msg["public_key"]; // get the public key
    User* user = new User(publicKey); // create a new user
    addConnectedClient(user->getFingerprint(), user); // add the user to the connected clients
    sendClientUpdate(); // send a client update (not sure if need to do this)
}

void Server::handleChatMessage(websocketpp::connection_hdl hdl, const std::string& message) {
    // todo: implement chat message handling
    // User* user = findUserByHandle(hdl); // find the user by handle
    // if (sender) {
    //     json msg = json::parse(message);
    //     std::vector<std::string> destinations = msg["destinations"];
    //     std::string iv = msg["iv"];
    //     std::vector<std::string> symmKeys = msg["symm_keys"];
    //     json innerChat = msg["chat"];
    //     json chatMessage = createChatMessage(destinations, iv, symmKeys, innerChat);
    //     broadcastToClients(chatMessage.dump());
    // }
    // not sure if this is correct but could be something along these lines?
}

void Server::handlePublicChatMessage(websocketpp::connection_hdl hdl, const std::string& message) {
    // todo: implement public chat message handling
}

void Server::handleClientListRequest(websocketpp::connection_hdl hdl) {
    // todo: implement client list request handling
    std::vector<ServerInfo> serverInfos;
    for (const auto& server : neighbourhood->getServers()) {
        ServerInfo info;
        info.address = server->getAddress();

        for (const auto& client : server->getConnectedClients()) {
            info.clients.push_back(client.first);
        }
        serverInfos.push_back(info);
    }

    json clientList = createClientList(serverInfos);
    server.send(hdl, clientList.dump(), websocketpp::frame::opcode::text);
}

void Server::sendClientUpdate() {
    std::vector<std::string> clients;
    for (const auto& client : connectedClients) {
        clients.push_back(client.first);
    }
    json clientUpdate = createClientUpdate(clients);
    broadcastToClients(clientUpdate.dump());
    // todo: implement sending client updates to other servers
}

void Server::handleClientUpdateRequest(const std::string& serverAddress) {
    // todo: implement handling client update requests from other servers
    json clientUpdateRequest = createClientUpdateRequest();
    relayMessage(clientUpdateRequest.dump(), serverAddress);
}


std::string Server::handleFileUpload(const std::string& fileData) {
    // todo: implement file upload handling
    boost::uuids::uuid uuid = boost::uuids::random_generator()(); //generate unique filename
    string filename = to_string(uuid); 
    ofstream ofs(filename, ios::binary);
    ofs << fileData;
    ofs.close();
    return "/api/download/" + filename;
}

std::string Server::handleFileRetrieve(const std::string& fileUrl) {
    // todo: implement file retrieval
    ifstream ifs(fileUrl, ios::binary);
    if (ifs) {
        string content((istreambuf_iterator<char>(ifs)), istreambuf_iterator<char>());
        return content;
    }
    return "file content not found";
}

void Server::startHTTPServer() {

    httpServer.Post("/api/upload", [this](const httplib::Request& req, httplib::Response& res) {
        auto file = req.get_file_value("file");
        string fileData = file.content;
        string fileUrl = handleFileUpload(fileData);
        json response;
        response["file_url"] = fileUrl;
        res.set_content(response.dump(), "application/json");
    });

    httpServer.Get(R"(/api/download/(.*))", [this](const httplib::Request& req, httplib::Response& res) {
        string fileUrl = req.matches[1];
        string fileContent = handleFileRetrieve(fileUrl);
        if (!fileContent.empty()) {
            res.set_content(fileContent, "application/octet-stream");
            res.set_header("Content-Disposition", "attachment; filename=" + fileUrl);
        } else {
            res.status = 404;
            res.set_content("file not found", "text/plain");
        }
    });

    httpServer.listen("0.0.0.0", 8080);
}

void Server::stopHTTPServer() { // call to stop the HTTP server
    httpServer.stop();
}

std::string Server::encryptMessage(const std::string& message, const std::string& recipientPublicKey) {
    // todo: implement message encryption
    return "";
}

std::string Server::decryptMessage(const std::string& encryptedMessage, const std::string& privateKey) {
    // todo: implement message decryption
    return "";
}

void Server::updateConnectedClients(const std::string& fingerprint, bool isConnected) {
    // todo: implement updating connected clients list
    if (isConnected) {
        // add the client to the connected clients
        User* user = new User(fingerprint); // assuming user can be created with just fingerprint 
        addConnectedClient(fingerprint, user);
    } else {
        // remove the client from the connected clients
        removeConnectedClient(fingerprint);
    }
    sendClientUpdate(); // send a client update to other servers
}

std::string Server::getAddress() const {
    return address; // Return the address of the server
}
