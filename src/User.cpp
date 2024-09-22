// LOCAL LIBRARIES
#include "include/User.h"
#include <string>
#include <iostream>

#include <iomanip>
#include <sstream>

// OPENSSL LIBRARIES
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>



User::User(const std::string &name) : name(name), publicKey(nullptr), privateKey(nullptr) {
    generateKeyPair();
    calculateFingerprint();
}

User::~User() {
    // todo: implement destructor

    if (privateKey) {
        RSA_free(privateKey);  // Free the private key
    }

    if (publicKey) {
        RSA_free(publicKey);  // Free the public key
    }
}

std::string User::getName() const {
    // todo: implement getname

    return name;
}

RSA* User::getPublicKey() const {
    // todo: implement getpublickey

    return publicKey;
}

RSA* User::getPrivateKey() const {
    // todo: implement getprivatekey
    return privateKey;
}

std::string User::getFingerprint() const {
    // todo: implement getfingerprint
    return fingerprint;
}

std::string User::getPublicKeyPEM() const {
    // todo: implement getpublickeypem
    return publicKeyPEM;
}

void User::generateKeyPair() {
    // todo: implement generatekeypair

    // Create a new RSA key
    RSA* rsa = RSA_new();
    BIGNUM* bne = BN_new();

    // Set public exponent to 65537
    BN_set_word(bne, RSA_F4);

    // Generate the RSA key pair
    if (!RSA_generate_key_ex(rsa, 2048, bne, nullptr)) {

        // Error handling
        ERR_print_errors_fp(stderr); // Might remove
        RSA_free(rsa);
        BN_free(bne);
        throw std::runtime_error("Failed to generate RSA key pair");
    }

    // Assign the generated keys to the class members
    privateKey = RSAPrivateKey_dup(rsa);
    publicKey = RSAPublicKey_dup(rsa);

    // Free RSA and BIGNUM
    RSA_free(rsa);
    BN_free(bne);

    // Check for successful duplication
    if (!privateKey || !publicKey) {
        throw std::runtime_error("Failed to duplicate RSA keys");
    }


    // Create Basic Input/Output
    BIO* bio = BIO_new(BIO_s_mem());

    // Write the RSA public key in SPKI format to the BIO
    if (!PEM_write_bio_RSA_PUBKEY(bio, publicKey)) {
        BIO_free(bio);
        throw std::runtime_error("Failed to export public key in SPKI format");
    }

    // Get the PEM data from the BIO
    char* pem_key = nullptr;
    long pem_size = BIO_get_mem_data(bio, &pem_key);
    publicKeyPEM = std::string(pem_key, pem_size);

    // Free the BIO
    BIO_free(bio);

}

void User::calculateFingerprint() {
    // todo: implement calculatefingerprint

    // Check if publicKeyPEM is empty
    if (publicKeyPEM.empty()) {
        throw std::runtime_error("Public key not available");
    }

    // Create a SHA256 context and hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    // Update the context with the public key PEM data
    SHA256_Update(&sha256, publicKeyPEM.data(), publicKeyPEM.length());

    // Finalize the hash
    SHA256_Final(hash, &sha256);

    // Convert the hash to a hexadecimal string
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    // Convert stringstream to string and save to fingerprint
    fingerprint = ss.str();

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
