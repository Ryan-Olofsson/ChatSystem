// LOCAL LIBRARIES
#include "include/Neighbourhood.h"
#include "include/Server.h"

using namespace std;

Neighbourhood::Neighbourhood() {
    // constructor implementation
}

Neighbourhood::~Neighbourhood() {
    // destructor implementation
}

void Neighbourhood::addServer(Server* server) {
    servers.push_back(server);
}

void Neighbourhood::removeServer(Server* server) {
    servers.erase(remove(servers.begin(), servers.end(), server), servers.end());
}

std::vector<Server*> Neighbourhood::getServers() const {
    return servers;
}

Server* Neighbourhood::findServer(const std::string& address) const {
    // find server implementation
    for (auto server : servers) {
        if (server->getAddress() == address) {
            return server;
        }
    }
    return nullptr;
}

