// LOCAL LIBRARIES
#include "include/User.h"
#include "include/njson.hpp"
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>


// OPENSSL LIBRARIES
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>



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

    // May need to change publicKeyPEM to publicKey

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

std::string User::encryptMessage(const std::string &message, RSA* publicKey) const {
    // todo: implement encryptmessage

    // Define AES key and IV
    unsigned char aesKey[32], iv[16];
    
    // Generate AES key and IV using random bytes
    if (!RAND_bytes(aesKey, sizeof(aesKey)) || !RAND_bytes(iv, sizeof(iv))) {
        throw std::runtime_error("Failed to generate AES key or IV");
    }

    // Create a new EVP_CIPHER_CTX
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    // Define length variables and ciphertext vector with padding for GCM
    int len, ciphertext_len;
    std::vector<unsigned char> ciphertext(message.size() + 16);

    // Initialize encryption operation with AES-256-GCM and the key and IV
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aesKey, iv) != 1 ||

        // Encrypts message and the output is placed in ciphertext with len being the number of bytes encrypted
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(message.data()), message.size()) != 1 ||

        // Finalizes the encryption process and adds the authentication tag to the ciphertext
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt message with AES-GCM");
    }
    ciphertext_len = len;

    // Encrypt the AES key using the RSA public key, stores result in encryptedKey
    std::vector<unsigned char> encryptedKey(RSA_size(publicKey));
    if (RSA_public_encrypt(sizeof(aesKey), aesKey, encryptedKey.data(), publicKey, RSA_PKCS1_OAEP_PADDING) == -1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt AES key with RSA");
    }

    // Free the EVP_CIPHER_CTX
    EVP_CIPHER_CTX_free(ctx);

    // Construct the final encrypted message
    std::string result;
    result.append(reinterpret_cast<char*>(iv), sizeof(iv));
    result.append(reinterpret_cast<char*>(encryptedKey.data()), encryptedKey.size());
    result.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);

    return result;
}

std::string User::decryptMessage(const std::string &encryptedMessage, RSA* privateKey) const {
    // todo: implement decryptmessage

    // Extract the IV, encrypted AES key, and ciphertext from the encrypted message
    const unsigned char* iv = reinterpret_cast<const unsigned char*>(encryptedMessage.data());
    const unsigned char* encryptedKey = iv + 16;
    const unsigned char* ciphertext = encryptedKey + RSA_size(privateKey);

    // Decrypt the encryptedKey using the RSA private key, stores result in aesKey
    unsigned char aesKey[32];
    if (RSA_private_decrypt(RSA_size(privateKey), encryptedKey, aesKey, privateKey, RSA_PKCS1_OAEP_PADDING) == -1) {
        throw std::runtime_error("Failed to decrypt AES key with RSA");
    }

    // Create a new EVP_CIPHER_CTX
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    // Define length variables and plaintext vector with a size equal to encryptedKey
    int len, plaintext_len;
    std::vector<unsigned char> plaintext(encryptedMessage.size() - 16 - RSA_size(privateKey));

    // Initialize decryption operation with AES-256-GCM and the key and IV
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aesKey, iv) != 1 ||

        // Decrypts ciphertext and the output is placed in plaintext with len being the number of bytes decrypted
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, encryptedMessage.size() - 16 - RSA_size(privateKey)) != 1 ||

        // Finalizes the decryption process and extracts the authentication tag from the ciphertext
        EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt message with AES-GCM");
    }
    plaintext_len = len;

    // Free the EVP_CIPHER_CTX
    EVP_CIPHER_CTX_free(ctx);

    // Convert the plaintext to a string and return it
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

std::string User::signMessage(const std::string &message) const {
    // todo: implement signmessage

    return "";
}

bool User::verifySignature(const std::string &message, const std::string &signature, RSA* signerPublicKey) const {
    // todo: implement verifysignature

    return false;
}

void User::sendMessage(const std::string& message) const { //eventually need this? not sure, only adding to remove errors for now.
    // Implementation to send a message to the user
    // This could involve using the WebSocket connection handle (handle)
    // to send the message through the WebSocket connection.
    // For example:
    // server.send(handle, message, websocketpp::frame::opcode::text);
}