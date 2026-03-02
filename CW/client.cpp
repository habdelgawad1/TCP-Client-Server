#include <iostream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "common.h"
#include "security.h"
using namespace std;

int main() {
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr = {AF_INET, htons(SERVER_PORT)};
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    if (connect(client_socket, (sockaddr*)&addr, sizeof(addr)) != 0) {
        cout << "Connection failed" << endl;
        return 1;
    }
    cout << "Connected to server" << endl;
    
    DiffieHellman dh;
    XORCipher cipher;
    
    // Key exchange
    dh.generateKeys();
    
    char buffer[BUFFER_SIZE];
    recv(client_socket, buffer, BUFFER_SIZE, 0);
    long long server_key = stoll(string(buffer));
    
    string my_key = to_string(dh.getPublicKey()) + "\n";
    send(client_socket, my_key.c_str(), my_key.length(), 0);
    
    dh.computeSharedSecret(server_key);
    cipher.setKey(dh.getSharedSecret());
    
    cout << "Encryption established. Enter commands (exit to quit):" << endl;
    
    // Command loop
    string command;
    while (getline(cin, command)) {
        if (command == "exit") break;
        
        string encrypted = cipher.encrypt(command);
        string hex = cipher.toHex(encrypted);
        
        send(client_socket, hex.c_str(), hex.length(), 0);
        cout << "Sent: " << command << endl;
    }
    
    close(client_socket);
    return 0;
}