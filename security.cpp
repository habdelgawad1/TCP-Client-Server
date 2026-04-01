#include "security.h"
#include "common.h"     // For DH_PRIME, DH_GENERATOR constants
#include <random>       // For random number generation
#include <sstream>      // For string stream operations
#include <iomanip>      // For hex formatting
#include <openssl/evp.h>   // For AES encryption
#include <openssl/hmac.h>  // For HMAC
#include <openssl/sha.h>   // For SHA256
#include <cstring>      // For memcpy
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
 * Initialize AES Cipher Key
 * Derives a 256-bit key from the numeric shared secret using SHA256.
 */
void AESCipher::setKey(long long secret) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    string secret_str = to_string(secret);
    SHA256((unsigned char*)secret_str.c_str(), secret_str.length(), hash);
    memcpy(key, hash, 32);  // Copy first 32 bytes for 256-bit AES key
}

// AES Encryption (AES-256-CBC with PKCS7 padding)
string AESCipher::encrypt(const string& text) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[EVP_MAX_IV_LENGTH] = {0};  // IV of zeros for simplicity
    
    int len = 0;
    int ciphertext_len = 0;
    unsigned char ciphertext[text.length() + EVP_MAX_BLOCK_LENGTH];
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)text.c_str(), text.length());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    
    return string((char*)ciphertext, ciphertext_len);
}

// AES Decryption (AES-256-CBC with PKCS7 padding)
string AESCipher::decrypt(const string& text) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[EVP_MAX_IV_LENGTH] = {0};  // IV of zeros for simplicity
    
    int len = 0;
    int plaintext_len = 0;
    unsigned char plaintext[text.length() + EVP_MAX_BLOCK_LENGTH];
    
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, (unsigned char*)text.c_str(), text.length());
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    
    return string((char*)plaintext, plaintext_len);
}

/**
 * Convert Binary Data to Hexadecimal
 * This prevents issues with null bytes and control characters in TCP streams.
 * Each byte becomes two hex digits
 */
string AESCipher::toHex(const string& data) {
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
string AESCipher::fromHex(const string& hex) {
    string result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        result += (char)stoll(hex.substr(i, 2), nullptr, 16);
    }
    return result;
}

/**
 * Compute HMAC-SHA256 for server authentication
 * Uses the shared secret as the HMAC key
 */
string computeHMAC(const string& data, long long secret) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len = 0;
    
    string secret_str = to_string(secret);
    HMAC(EVP_sha256(), secret_str.c_str(), secret_str.length(),
         (unsigned char*)data.c_str(), data.length(), result, &result_len);
    
    stringstream ss;
    ss << hex << setfill('0');
    for (unsigned int i = 0; i < result_len; i++) {
        ss << setw(2) << (unsigned int)result[i];
    }
    return ss.str();
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

bool isCommandAllowed(int level, const string& command){
    if (level == ADMIN) {
        // Full command access.
        return true;
    }

    // USER and GUEST cannot perform deletion operations.
    if (command == "rm" || command.find("rm ") == 0 ||
        command == "rmdir" || command.find("rmdir ") == 0) {
        return false;
    }

    if (level == USER) {
        // USER level: read, copy, create, file operations, and navigation.
        return (command == "ls" || command.find("ls ") == 0 ||
                command == "cat" || command.find("cat ") == 0 ||
                command == "pwd" || command.find("pwd ") == 0 ||
                command == "cd" || command.find("cd ") == 0 ||
                command == "cp" || command.find("cp ") == 0 ||
                command == "mv" || command.find("mv ") == 0 ||
                command == "touch" || command.find("touch ") == 0 ||
                command == "mkdir" || command.find("mkdir ") == 0 ||
                command == "grep" || command.find("grep ") == 0 ||
                command == "find" || command.find("find ") == 0 ||
                command == "head" || command.find("head ") == 0 ||
                command == "tail" || command.find("tail ") == 0 ||
                command == "echo" || command.find("echo ") == 0);
    }

    if (level == GUEST) {
        // GUEST level: basic read-only commands only.
        return (command == "ls" || command.find("ls ") == 0 ||
                command == "cat" || command.find("cat ") == 0 ||
                command == "cd" || command.find("cd ") == 0 ||
                command == "pwd" || command.find("pwd ") == 0 ||
                command == "head" || command.find("head ") == 0 ||
                command == "tail" || command.find("tail ") == 0 ||
                command == "grep" || command.find("grep ") == 0);
    }

    // Unknown levels are denied by default.
    return false;
}

