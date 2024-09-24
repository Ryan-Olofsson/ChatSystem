#ifndef JSONFUNCTIONS_HPP
#define JSONFUNCTIONS_HPP

#include <njson.hpp>
#include <string>
#include <vector>
using namespace std;
using json = nlohmann::json;

struct ServerInfo {
    string address;
    vector<string> clients;
};



// Function declarations

json createSignedMessage(const json& data);
json createClientUpdate(const std::vector<std::string>& clients);
json createClientUpdateRequest();

// Extracted function headers
json helloMessage(const std::string& publicKey);
json createChatMessage(const std::vector<std::string>& destinations, const std::string& iv, const std::vector<std::string>& symmKeys, const json& innerChat);
json innerChatMessage(const std::vector<std::string>& participantsSignatures, const std::string& message);
std::string encodeFingerprint(const std::string& fingerprint);
json publicChat(const std::string& fingerprint, const std::string& message);
json createClientList(const std::vector<ServerInfo>& servers);

#endif // JSONFUNCTIONS_HPP