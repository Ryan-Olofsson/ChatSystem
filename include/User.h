#ifndef USER_H
#define USER_H

// LOCAL LIBRARIES
#include <string>

// OPENSSL LIBRARIES
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

class User {
public:
    // constructor and destructor
    User(const std::string& name);
    ~User();

    // getters
    std::string getName() const;
    RSA* getPublicKey() const;
    RSA* getPrivateKey() const;
    std::string getFingerprint() const;
    std::string getPublicKeyPEM() const;
    
    // encryption and decryption methods
    std::string encryptMessage(const std::string& message, RSA* publicKey) const;
    std::string decryptMessage(const std::string& encryptedMessage, RSA* privateKey) const;

    // signing and verification methods
    std::string signMessage(const std::string& message) const;
    bool verifySignature(const std::string& message, const std::string& signature, RSA* signerPublicKey) const;

private:
    // user attributes
    std::string name;
    RSA* publicKey;
    RSA* privateKey;
    std::string fingerprint;
    std::string publicKeyPEM;

    // helper methods
    void generateKeyPair();
    void calculateFingerprint();
};

#endif 

