/**
 * SECURITY.H - Cryptographic Security Module Header
 * 
 * This header defines the security classes and functions used for:
 * 1. Diffie-Hellman Key Exchange - Secure key agreement protocol
 * 2. XOR Cipher - Symmetric encryption using the shared secret
 * 3. Utility functions for modular exponentiation and random numbers
 */

#ifndef SECURITY_H
#define SECURITY_H

#include <string>
using namespace std;

/**
 * DiffieHellman Class
 * 
 * Implements the Diffie-Hellman key exchange algorithm:
 * 1. Each party generates a private key (random)
 * 2. Each party computes public key = g^private mod p
 * 3. Parties exchange public keys
 * 4. Each computes shared secret = other_public^private mod p
 * 
 * Security: Even if public keys are intercepted, the shared secret
 * cannot be computed without knowing one of the private keys
 */
class DiffieHellman {
private:
    long long private_key;    // Secret random number (never transmitted)
    long long public_key;     // g^private_key mod p (safe to transmit)
    long long shared_secret;  // Final agreed secret for encryption
    
public:
    void generateKeys();                              // Generate private/public key pair
    long long getPublicKey() const { return public_key; }        // Get public key for transmission
    void computeSharedSecret(long long other_key);   // Compute shared secret from other's public key
    long long getSharedSecret() const { return shared_secret; }  // Get the computed shared secret
};

/**
 * XORCipher Class
 * 
 * Simple symmetric cipher using XOR operation:
 * - Encryption: plaintext XOR key = ciphertext
 * - Decryption: ciphertext XOR key = plaintext (XOR is self-inverse)
 * 
 * Note: XOR is simple but not cryptographically strong for real applications.
 * Used here for educational purposes. Production systems should use AES.
 */
class XORCipher {
private:
    string key;  // The encryption key derived from shared secret
    
public:
    void setKey(long long secret);           // Convert shared secret to encryption key
    string encrypt(const string& text);      // Encrypt/decrypt text (XOR is symmetric)
    string toHex(const string& data);        // Convert binary data to hex string
    string fromHex(const string& hex);       // Convert hex string back to binary
};

/**
 * Utility Functions
 */

// Modular exponentiation: compute (base^exp) mod mod efficiently
// Used in Diffie-Hellman calculations - prevents integer overflow
long long power_mod(long long base, long long exp, long long mod);

// Generate cryptographically random number for private keys
long long random_number();

#endif // SECURITY_H