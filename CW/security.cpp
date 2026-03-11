/**
 * SECURITY.CPP - Cryptographic Security Module Implementation
 * 
 * Contains the actual implementation of Diffie-Hellman key exchange
 * and XOR cipher encryption/decryption functionality.
 */

#include "security.h"
#include "common.h"     // For DH_PRIME, DH_GENERATOR constants
#include <random>       // For random number generation
#include <sstream>      // For string stream operations
#include <iomanip>      // For hex formatting
using namespace std;

/**
 * Generate Diffie-Hellman Key Pair
 * 
 * Creates a random private key and computes corresponding public key.
 * Private key: random number in range [1, p-2]
 * Public key: g^private_key mod p
 * 
 * Uses large prime p = 2^31 - 1 and generator g = 2 from common.h
 */
void DiffieHellman::generateKeys() {
    // Generate random private key in valid range [1, p-2]
    private_key = random_number() % (DH_PRIME - 2) + 1;
    
    // Compute public key: g^private_key mod p
    // This is safe to share - discrete log problem makes private key hard to recover
    public_key = power_mod(DH_GENERATOR, private_key, DH_PRIME);
}

/**
 * Compute Shared Secret
 * 
 * Uses the other party's public key and our private key to compute
 * the shared secret that both parties will have:
 * 
 * Client computes: server_public^client_private mod p
 * Server computes: client_public^server_private mod p
 * 
 * Both results are identical due to modular arithmetic:
 * (g^a)^b = (g^b)^a = g^(a*b) mod p
 */
void DiffieHellman::computeSharedSecret(long long other_key) {
    shared_secret = power_mod(other_key, private_key, DH_PRIME);
}

/**
 * Initialize XOR Cipher Key
 * 
 * Converts the numeric shared secret into a string key for XOR operations.
 * Extends the key by repeating it to ensure sufficient length for encryption.
 */
void XORCipher::setKey(long long secret) {
    stringstream ss;
    ss << secret;                    // Convert number to string
    key = ss.str();
    while (key.length() < 8) {       // Ensure minimum key length
        key += key;                  // Repeat key if too short
    }
}

/**
 * XOR Encryption/Decryption
 * 
 * Performs XOR operation between text and key.
 * Since XOR is self-inverse: encrypt(encrypt(text)) = text
 * This same function handles both encryption and decryption.
 * 
 * Process: Each character is XORed with corresponding key character.
 * Key is repeated cyclically if shorter than text.
 */
string XORCipher::encrypt(const string& text) {
    string result;
    for (size_t i = 0; i < text.length(); i++) {
        // XOR each character with corresponding key character (cycling through key)
        result += text[i] ^ key[i % key.length()];
    }
    return result;
}

/**
 * Convert Binary Data to Hexadecimal
 * 
 * Converts encrypted binary data to hex string for safe transmission.
 * This prevents issues with null bytes and control characters in TCP streams.
 * Each byte becomes two hex digits (00-FF).
 */
string XORCipher::toHex(const string& data) {
    stringstream ss;
    ss << hex << setfill('0');       // Use hex format with zero padding
    for (unsigned char c : data) {
        ss << setw(2) << (unsigned int)c;  // Each byte becomes 2 hex digits
    }
    return ss.str();
}

/**
 * Convert Hexadecimal to Binary Data
 * 
 * Converts received hex string back to original binary data.
 * Each pair of hex digits becomes one byte.
 * Used to restore encrypted data after transmission.
 */
string XORCipher::fromHex(const string& hex) {
    string result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        // Convert each pair of hex digits to one byte
        result += (char)stoll(hex.substr(i, 2), nullptr, 16);
    }
    return result;
}

/**
 * Modular Exponentiation
 * 
 * Efficiently computes (base^exp) mod mod using binary exponentiation.
 * This prevents integer overflow that would occur with naive base^exp calculation.
 * 
 * Algorithm: Square-and-multiply method
 * - If exp bit is 1: multiply result by current base power
 * - Square base power for next bit
 * - Shift exp right to process next bit
 * 
 * Time complexity: O(log exp) instead of O(exp)
 * Essential for Diffie-Hellman with large numbers
 */
long long power_mod(long long base, long long exp, long long mod) {
    long long result = 1;
    base %= mod;                    // Reduce base to avoid overflow
    
    while (exp > 0) {
        if (exp & 1) {              // If current bit is 1
            result = (result * base) % mod;
        }
        base = (base * base) % mod; // Square base for next bit
        exp >>= 1;                  // Shift to next bit
    }
    return result;
}

/**
 * Cryptographically Secure Random Number Generator
 * 
 * Generates random numbers for private key generation.
 * Uses hardware random device as seed for Mersenne Twister.
 * 
 * Returns: Random number in range [1000, 1001000)
 * This range ensures sufficient entropy while staying within safe bounds.
 */
long long random_number() {
    static random_device rd;         // Hardware random number generator
    static mt19937 gen(rd());        // Mersenne Twister seeded with hardware RNG
    return gen() % 1000000 + 1000;   // Return number in safe range
}