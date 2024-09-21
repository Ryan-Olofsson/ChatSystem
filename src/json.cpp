#include <stdint.h>
#include <string>
#include <vector>
#include <json.hpp>
#include <base64.hpp>

using json = nlohmann::json;
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

static uint32_t m_counter = 0;

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

json createSignedMessage(const json& data) {
    json message;
    message["type"] = "signed_data";
    message["data"] = data;
    message["counter"] = m_counter;

    string messageStr = message.dump();
    string signatureInput = messageStr + to_string(m_counter);
    string signature = macaron::Base64::Encode(signatureInput);

    message["signature"] = signature;
    m_counter++;
    return message;
}


json helloMessage(const string& publicKey) {

    json helloData;
    helloData["type"] = "hello";
    helloData["public_key"] = publicKey; // still needs implementation

    return createSignedMessage(helloData);
}

json createChatMessage(const vector<string>& destinations, const string& iv, const vector<string>& symmKeys, const json& innerChat) {
    json chatData;
    chatData["type"] = "chat";
    chatData["destinations"] = destinations; // still needs implementation
    chatData["iv"] = iv; // still needs implementation
    chatData["symm_keys"] = symmKeys; // still needs implementation
    chatData["chat"] = innerChat;

    return createSignedMessage(chatData);
    
}

json innerChatMessage(const vector<string>& participants, const string& message) { // tracking of participants and whatnot needs implementation
    json chatInner;
    vector<string> base64Participants;
    for (const auto& participant : participants) {
        base64Participants.push_back(encodeFingerprint(participant));
    }
    chatInner["participants"] = base64Participants; // base64 encoded list of fingerprints of participants, starting with sender

    chatInner["message"] = message;


    return chatInner;
}

string encodeFingerprint(const string& fingerprint) { // helper function to encode a fingerprint in base64
    return macaron::Base64::Encode(fingerprint);
}


json publicChat(const string& fingerprint, const string& message) {
    json publicChatData;
    publicChatData["type"] = "public_chat";
    publicChatData["sender"] = encodeFingerprint(fingerprint); 
    publicChatData["message"] = message;
    return createSignedMessage(publicChatData); // unsure if we need public chat but got it here just in case
}

json createClientList(const vector<ServerInfo>& servers) { //still needs server tracking implementation?
    json clientList;
    clientList["type"] = "client_list";
    clientList["servers"] = json::array();
    
    for (const auto& server : servers) { // still needs implementation
        json serverInfo; 
        serverInfo["address"] = server.address; 
        serverInfo["clients"] = json::array();
        
        for (const auto& client : server.clients) {
            serverInfo["clients"].push_back(client); // add each client to the clients array
    }
    clientList["servers"].push_back(serverInfo);
    }
    return clientList;
}
int main() {




}

