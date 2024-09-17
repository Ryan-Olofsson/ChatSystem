#include <stdint.h>
#include <string>
#include <vector>
using namespace std; 


// #define MAX_IP_LEN 16
// #define MESSAGE_TYPE_LEN 30
// #define MAX_CLIENTS 100
// #define MAX_KEY_LEN 256
// #define MAX_DATA_LEN 1024
// #define MAX_SIGNATURE_LEN 256
// #define MAX_SERVERS 15
// #define MAX_PARTICIPANTS 30
// #define MAX_FINGERPRINTS_LEN 64
// #define MAX_DESTINATIONS 15
// #define MAX_CHAT_MSG_LEN 1024
// #define MAX_AES_IV_LEN 16
// #define MAX_ENCRYPTED_KEY_LEN 256



struct ClientMessageStructure {
    string type;
    string data;
    uint32_t counter;
    string signature;
};

struct ClientHelloData{
    string type;
    string public_key;
};

struct ClientHelloMessage {
    ClientHelloData data;
};

struct ServerClientListRequest {
    string type;
};

struct ServerInfo {
    string address;
    vector<string> clients;
    int client_count;
};

struct ClientList {
    string type;
    vector<ServerInfo> servers;
};

struct ServerHelloData {
    string type;
    string sender;
};

struct  ServerHelloMessage {
    ServerHelloData data;
};

struct ServerClientUpdateRequest {
    string type;
};

struct ServerClientUpdate{
    string type;
    vector<string> clients;
    int client_count;
};

struct ChatMessage {
    string participants;
    string message;
};

struct ChatDataStructure {
    string type;
    vector<string> destinations;
    string iv;
    vector<string> symm_keys;
    string chat;
};


int main() {

}