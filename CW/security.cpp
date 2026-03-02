#include "security.h"
#include "common.h"
#include <random>
#include <sstream>
#include <iomanip>
using namespace std;

void DiffieHellman::generateKeys() {
    private_key = random_number() % (DH_PRIME - 2) + 1;
    public_key = power_mod(DH_GENERATOR, private_key, DH_PRIME);
}

void DiffieHellman::computeSharedSecret(long long other_key) {
    shared_secret = power_mod(other_key, private_key, DH_PRIME);
}

void XORCipher::setKey(long long secret) {
    stringstream ss;
    ss << secret;
    key = ss.str();
    while (key.length() < 8) key += key;
}

string XORCipher::encrypt(const string& text) {
    string result;
    for (size_t i = 0; i < text.length(); i++) {
        result += text[i] ^ key[i % key.length()];
    }
    return result;
}

string XORCipher::toHex(const string& data) {
    stringstream ss;
    ss << hex << setfill('0');
    for (unsigned char c : data) {
        ss << setw(2) << (unsigned int)c;
    }
    return ss.str();
}

string XORCipher::fromHex(const string& hex) {
    string result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        result += (char)stoll(hex.substr(i, 2), nullptr, 16);
    }
    return result;
}

long long power_mod(long long base, long long exp, long long mod) {
    long long result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

long long random_number() {
    static random_device rd;
    static mt19937 gen(rd());
    return gen() % 1000000 + 1000;
}