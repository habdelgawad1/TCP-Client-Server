#include <iostream>
#include <string>
#include <WinSock2.h>
#include "common.h"
#include "security.h"
using namespace std;

#pragma comment(lib, "ws2_32.lib")

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr = {AF_INET, htons(SERVER_PORT), {INADDR_ANY}};
    
    bind(server_socket, (sockaddr*)&addr, sizeof(addr));
    listen(server_socket, 1);
    cout << "Server listening on port " << SERVER_PORT << endl;
    
    while (true) {
        SOCKET client = accept(server_socket, 0, 0);
        cout << "Client connected" << endl;
        
        DiffieHellman dh;
        XORCipher cipher;
        
        // Key exchange
        dh.generateKeys();
        string my_key = to_string(dh.getPublicKey()) + "\n";
        send(client, my_key.c_str(), my_key.length(), 0);
        
        char buffer[BUFFER_SIZE];
        recv(client, buffer, BUFFER_SIZE, 0);
        long long client_key = stoll(string(buffer));
        
        dh.computeSharedSecret(client_key);
        cipher.setKey(dh.getSharedSecret());
        
        // Receive commands
        while (true) {
            int len = recv(client, buffer, BUFFER_SIZE, 0);
            if (len <= 0) break;
            
            buffer[len] = 0;
            string hex(buffer);
            string encrypted = cipher.fromHex(hex);
            string command = cipher.encrypt(encrypted); // XOR decrypt
            
            cout << "Command: " << command << endl;
        }
        
        closesocket(client);
        cout << "Client disconnected" << endl;
    }
    
    WSACleanup();
    return 0;
}