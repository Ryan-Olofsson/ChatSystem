#ifndef SERVER_H
#define SERVER_H

// LOCAL LIBRARIES
#include <string>
#include <vector>
#include <map>
#include "User.h"

// WEBSOCKETS LIBRARIES
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>


class Server {
public:
    Server(const std::string& address, int port);
    ~Server();

    void start();
    void stop();
    void setNeighbourhood(Neighbourhood* neighbourhood);
    void addConnectedClient(const std::string& fingerprint, User* user);
    void removeConnectedClient(const std::string& fingerprint);

private:
    std::string address;
    int port;
    std::map<std::string, User*> connectedClients;
    Neighbourhood* neighbourhood;
    websocketpp::server<websocketpp::config::asio> server;

    void onMessage(websocketpp::connection_hdl hdl, websocketpp::server<websocketpp::config::asio>::message_ptr msg);
    void relayMessage(const std::string& message, const std::string& destinationServer);
    void broadcastToClients(const std::string& message);
};

#endif 


