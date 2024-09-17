#ifndef NEIGHBOURHOOD_H
#define NEIGHBOURHOOD_H

#include <vector>
#include <string>

class Server;

class Neighbourhood {
public:
    Neighbourhood();
    ~Neighbourhood();

    void addServer(Server* server);
    void removeServer(Server* server);
    std::vector<Server*> getServers() const;
    Server* findServer(const std::string& address) const;

private:
    std::vector<Server*> servers;
};

#endif
