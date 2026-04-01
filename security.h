#ifndef SECURITY_H
#define SECURITY_H
#include <string>
using namespace std;

/**
 * Implements the Diffie-Hellman key exchange algorithm:
 * 1. Each party generates a private key (random)
 * 2. Each party computes public key = g^private mod p
 * 3. Parties exchange public keys
 * 4. Each computes shared secret = other_public^private mod p
 */
class DiffieHellman {
private:
    long long private_key;    // Secret random number
    long long public_key;     //g^private_key mod p 
    long long shared_secret;  
    
public:
    void generateKeys();                              
    long long getPublicKey() const { return public_key; }        
    void computeSharedSecret(long long other_key);   
    long long getSharedSecret() const { return shared_secret; } 
};

/**
 * AES-256-CBC symmetric cipher:
 */
class AESCipher {
private:
    unsigned char key[32];  // 256-bit key for AES-256
    
public:
    void setKey(long long secret);           // Derive 256-bit key from shared secret
    string encrypt(const string& text);      // Encrypt text with AES-256-CBC
    string decrypt(const string& text);      // Decrypt text with AES-256-CBC
    string toHex(const string& data);        // Convert binary data to hex string
    string fromHex(const string& hex);       // Convert hex string back to binary
};

// Server authentication function using HMAC-SHA256
string computeHMAC(const string& data, long long secret);

// Password hashing function using SHA256
string hashPassword(const string& password);

// Modular exponentiation: compute (base^exp) mod mod efficiently
long long power_mod(long long base, long long exp, long long mod);
long long random_number();

bool isCommandAllowed(int level, const string& command);

#endif 