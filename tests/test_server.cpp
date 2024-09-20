#include <cassert>
#include <iostream>
#include "Server.h"

void test_server_init() {
    const std::string address = "127.0.0.1";
    const int port = 9002;

    Server server(address, port);

    // Check if the server is running after initialization
    assert(server.isRunning());

    std::cout << "Server initialization test passed." << std::endl;
}

int main() {
    test_server_init();
    return 0;
}
