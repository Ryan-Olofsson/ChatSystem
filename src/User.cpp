// LOCAL LIBRARIES
#include "include/User.h"
#include <string>

// OPENSSL LIBRARIES
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>


User::User(const std::string &name) : name(name), publicKey(nullptr), privateKey(nullptr) {
    generateKeyPair();
    calculateFingerprint();
}

User::~User() {
    // todo: implement destructor
}

std::string User::getName() const {
    // todo: implement getname
    return "";
}

RSA* User::getPublicKey() const {
    // todo: implement getpublickey
    return nullptr;
}

RSA* User::getPrivateKey() const {
    // todo: implement getprivatekey
    return nullptr;
}

std::string User::getFingerprint() const {
    // todo: implement getfingerprint
    return "";
}

void User::generateKeyPair() {
    // todo: implement generatekeypair
}

void User::calculateFingerprint() {
    // todo: implement calculatefingerprint
}

std::string User::encryptMessage(const std::string &message, RSA* recipientPublicKey) const {
    // todo: implement encryptmessage
    return "";
}

std::string User::decryptMessage(const std::string &encryptedMessage) const {
    // todo: implement decryptmessage
    return "";
}

std::string User::signMessage(const std::string &message) const {
    // todo: implement signmessage
    return "";
}

bool User::verifySignature(const std::string &message, const std::string &signature, RSA* signerPublicKey) const {
    // todo: implement verifysignature
    return false;
}
