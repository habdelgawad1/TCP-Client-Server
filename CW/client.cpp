#include <iostream>
#include <string> 
#include <sys/socket.h>    // Unix socket API
#include <netinet/in.h>    // Unix network structures
#include <arpa/inet.h>     // Unix address conversion functions
#include <unistd.h>        // Unix system calls (close, etc.)
#include "common.h"        
#include "security.h"      
using namespace std;

int main() {
    //Create TCP socket for communication
    //IPv4, SOCK_STREAM = TCP protocol
    int client_socket = socket(IP, SOCK_STREAM, 0);
    
    //Configure server address structure
    sockaddr_in addr = {IP, htons(SERVER_PORT)};  //Converts port to network byte order
    addr.sin_addr.s_addr = inet_addr("127.0.0.1"); 
    
    //Attempt to connect to the server
    if (connect(client_socket, (sockaddr*)&addr, sizeof(addr)) != 0) {
        cout << "Connection failed" << endl;
        return 1;
    }
    cout << "Connected to server" << endl;
    
    //Initialize cryptographic objects
    DiffieHellman dh;    
    XORCipher cipher;    
    
    //DIFFIE-HELLMAN KEY EXCHANGE PROTOCOL
    dh.generateKeys();
    
    // Receive server's public key
    char buffer[BUFFER_SIZE];
    recv(client_socket, buffer, BUFFER_SIZE, 0);           
    long long server_key = stoll(string(buffer));    
    
    // Send public key to the server
    string my_key = to_string(dh.getPublicKey()) + "\n";  
    send(client_socket, my_key.c_str(), my_key.length(), 0);
    
    //Calculate shared secret using server's public key and our private key
    dh.computeSharedSecret(server_key);
    
    //Initialize cipher with the shared secret
    cipher.setKey(dh.getSharedSecret());
    
    cout << "Encryption established. Enter commands (exit to quit):" << endl;
    
    //SECURE COMMAND LOOP
    string command;
    while (getline(cin, command)) {
        if (command == "exit") break;
        
        // Encrypt the command using XOR cipher with shared secret
        string encrypted = cipher.encrypt(command);
        
        // Convert encrypted binary data to hexadecimal
        string hex = cipher.toHex(encrypted);
        
        // Send encrypted command to server
        send(client_socket, hex.c_str(), hex.length(), 0);
        cout << "Sent: " << command << endl;
    }
    
    //Clean up and close connection
    close(client_socket);
    return 0;
}