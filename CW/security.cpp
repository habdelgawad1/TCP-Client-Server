#include "security.h"
#include "common.h"     // For DH_PRIME, DH_GENERATOR constants
#include <random>       // For random number generation
#include <sstream>      // For string stream operations
#include <iomanip>      // For hex formatting
using namespace std;

/**
 * Generate Diffie-Hellman Key Pair
 * Private key: random number in range [1, p-2]
 * Public key: g^private_key mod p
 * Uses large prime p = 2^31 - 1 and generator g = 2 from common.h
 */
void DiffieHellman::generateKeys() {
    private_key = random_number() % (DH_PRIME - 2) + 1;
    public_key = power_mod(DH_GENERATOR, private_key, DH_PRIME);
}

/**
 * Compute Shared Secret
 * Both results are identical due to modular arithmetic:
 * (g^a)^b = (g^b)^a = g^(a*b) mod p
 */
void DiffieHellman::computeSharedSecret(long long other_key) {
    shared_secret = power_mod(other_key, private_key, DH_PRIME);
}

/**
 * Initialize XOR Cipher Key
 * Converts the numeric shared secret into a string key for XOR operations.
 * Extends the key by repeating it to ensure sufficient length for encryption.
 */
void XORCipher::setKey(long long secret) {
    stringstream ss;
    ss << secret;                    
    key = ss.str();
    while (key.length() < 8) {       
        key += key;                  
    }
}

// XOR Encryption/Decryption
string XORCipher::encrypt(const string& text) {
    string result;
    for (size_t i = 0; i < text.length(); i++) {
        result += text[i] ^ key[i % key.length()];
    }
    return result;
}

/**
 * Convert Binary Data to Hexadecimal
 * This prevents issues with null bytes and control characters in TCP streams.
 * Each byte becomes two hex digits
 */
string XORCipher::toHex(const string& data) {
    stringstream ss;
    ss << hex << setfill('0');       
    for (unsigned char c : data) {
        ss << setw(2) << (unsigned int)c;  
    }
    return ss.str();
}

/**
 * Convert Hexadecimal to Binary Data
 * Converts received hex string back to original binary data.
 * Each pair of hex digits becomes one byte.
 */
string XORCipher::fromHex(const string& hex) {
    string result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        result += (char)stoll(hex.substr(i, 2), nullptr, 16);
    }
    return result;
}

/**
 * Efficiently computes (base^exp) mod mod using binary exponentiation.
 * This prevents integer overflow that would occur with naive base^exp calculation.
 * If exp bit is 1: multiply result by current base power
 * Square base power for next bit
 * Shift exp right to process next bit
 */
long long power_mod(long long base, long long exp, long long mod) {
    long long result = 1;
    base %= mod;                    // Reduce base to avoid overflow
    
    while (exp > 0) {
        if (exp & 1) {              
            result = (result * base) % mod;
        }
        base = (base * base) % mod; 
        exp >>= 1;                  
    }
    return result;
}

/**
 * Generates random numbers for private key generation.
 * Uses hardware random device as seed for Mersenne Twister.
 */
long long random_number() {
    static random_device rd;         // Hardware random number generator
    static mt19937 gen(rd());        // Mersenne Twister seeded with hardware RNG
    return gen() % 1000000 + 1000;   // Return number in safe range
}