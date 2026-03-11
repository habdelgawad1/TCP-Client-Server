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
 * Simple symmetric cipher using XOR operation:
 */
class XORCipher {
private:
    string key;  // Shared secret
    
public:
    void setKey(long long secret);           // Convert shared secret to encryption key
    string encrypt(const string& text);      // Encrypt/decrypt text
    string toHex(const string& data);        // Convert binary data to hex string
    string fromHex(const string& hex);       // Convert hex string back to binary
};

// Modular exponentiation: compute (base^exp) mod mod efficiently
long long power_mod(long long base, long long exp, long long mod);
long long random_number();

#endif 