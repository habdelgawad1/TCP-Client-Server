#include <iostream>
#include <string>
#include <sys/socket.h>    // Unix socket API
#include <netinet/in.h>    // Unix network structures  
#include <arpa/inet.h>     // Unix address conversion
#include <unistd.h>        // Unix system calls (close, etc.)
#include "common.h"        
#include "security.h"      
using namespace std;

int main() {
    // Create server socket
    int server_socket = socket(IP, SOCK_STREAM, 0);
    
    // Configure server address structure
    // INADDR_ANY means accept connections on any network interface
    sockaddr_in addr = {IP, htons(SERVER_PORT), {INADDR_ANY}};
    
    // Bind socket to the specified port and start listening
    bind(server_socket, (sockaddr*)&addr, sizeof(addr));
    listen(server_socket, 1);
    cout << "Server listening on port " << SERVER_PORT << endl;
    
    // Main Server Loop
    while (true) {
        int client = accept(server_socket, 0, 0);
        cout << "Client connected" << endl;
        
        DiffieHellman dh;    
        XORCipher cipher;  
        
        // Diffie-Hellman Key Exchange 
        dh.generateKeys();
        
        // Send public key to client
        string my_key = to_string(dh.getPublicKey()) + "\n";
        send(client, my_key.c_str(), my_key.length(), 0);
        
        // Receive client's public key
        char buffer[BUFFER_SIZE];
        recv(client, buffer, BUFFER_SIZE, 0);
        long long client_key = stoll(string(buffer));
        
        dh.computeSharedSecret(client_key);
        cipher.setKey(dh.getSharedSecret());
        
        // Secure Command Reception Loop
        while (true) {
            int len = recv(client, buffer, BUFFER_SIZE, 0);
            if (len <= 0) break; 
            
            // Null-terminate the received data
            buffer[len] = 0;
            
            string hex(buffer);                           
            string encrypted = cipher.fromHex(hex);       
            string command = cipher.encrypt(encrypted);   
            
            cout << "Command: " << command << endl;
        }
        
        // Clean up client connection 
        close(client);
        cout << "Client disconnected" << endl;
    }
    
    // Clean up server socket 
    close(server_socket);
    return 0;
}