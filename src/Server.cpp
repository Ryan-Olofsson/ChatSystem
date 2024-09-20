#include "include/Server.h"
#include <iostream>

// server constructor
Server::Server(const std::string& address, int port) : address(address), port(port), neighbourhood(nullptr) {
    
    // initialise server
    server.init_asio(); // asio server init
    server.set_message_handler(bind(&Server::onMessage, this, ::_1, ::_2)); // set message handler
    server.set_open_handler(bind(&Server::onOpen, this, ::_1)); // set open handler
    server.set_close_handler(bind(&Server::onClose, this, ::_1)); // set close handler

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
    stop();

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

void Server::start() {

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

void Server::stop() {

    // TODO: implement this:
    // check if the server is running
    // if the server is running:
    //   1. stop accepting new connections
    //   2. close all existing connections
    //   3. stop the asio io_service
    //   4. join any running server threads
    //   5. set a flag or state variable to indicate the server is stopped
    // log that the server has been stopped
    // if the server is not running, log that no action was needed
    
}

void Server::setNeighbourhood(Neighbourhood* neighbourhood) {

    // set the neighbourhood

}

void Server::addConnectedClient(const std::string& fingerprint, User* user) {

    // add a connected client

}

void Server::removeConnectedClient(const std::string& fingerprint) {

    // remove a connected client

}

void Server::onMessage(websocketpp::connection_hdl hdl, websocketpp::server<websocketpp::config::asio>::message_ptr msg) {

    // handle incoming messages

}

void Server::onOpen(websocketpp::connection_hdl hdl) {

    // this'll handle the connection open
    // e.g. add the client to connectedClients
    // and log the connection

}   

void Server::onClose(websocketpp::connection_hdl hdl) {

    // this'll handle the connection closure
    // e.g. remove the client from connectedClients
    // and log the disconnection

}

void Server::relayMessage(const std::string& message, const std::string& destinationServer) {

    // relay message to another server

}

void Server::broadcastToClients(const std::string& message) {

    // broadcast message to all connected clients

}


