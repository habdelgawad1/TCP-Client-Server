#ifndef SECURITY_H
#define SECURITY_H

#include <string>
using namespace std;

class DiffieHellman {
private:
    long long private_key, public_key, shared_secret;
    
public:
    void generateKeys();
    long long getPublicKey() const { return public_key; }
    void computeSharedSecret(long long other_key);
    long long getSharedSecret() const { return shared_secret; }
};

class XORCipher {
private:
    string key;
    
public:
    void setKey(long long secret);
    string encrypt(const string& text);
    string toHex(const string& data);
    string fromHex(const string& hex);
};

long long power_mod(long long base, long long exp, long long mod);
long long random_number();

#endif // SECURITY_H