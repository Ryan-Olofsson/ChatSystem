// LOCAL LIBRARIES
#include "Neighbourhood.h"
#include "Server.h"

Neighbourhood::Neighbourhood() {
    // constructor implementation
}

Neighbourhood::~Neighbourhood() {
    // destructor implementation
}

void Neighbourhood::addServer(Server* server) {
    // add server implementation
}

void Neighbourhood::removeServer(Server* server) {
    // remove server implementation
}

std::vector<Server*> Neighbourhood::getServers() const {
    // get servers implementation
    return servers;
}

Server* Neighbourhood::findServer(const std::string& address) const {
    // find server implementation
    return nullptr;
}

