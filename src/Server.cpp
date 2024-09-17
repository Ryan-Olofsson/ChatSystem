#include "include/Server.h"
#include <iostream>

Server::Server(const std::string& address, int port) : address(address), port(port), neighbourhood(nullptr) {
    // initialize server
}

Server::~Server() {
    // cleanup
}

void Server::start() {
    // start the server
}

void Server::stop() {
    // stop the server
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

void Server::relayMessage(const std::string& message, const std::string& destinationServer) {
    // relay message to another server
}

void Server::broadcastToClients(const std::string& message) {
    // broadcast message to all connected clients
}
