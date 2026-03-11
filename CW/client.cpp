/**
 * CLIENT.CPP - Secure TCP Client Implementation
 * 
 * PLATFORM: Ubuntu/Linux ONLY (Uses Unix socket API)
 * DEPENDENCIES: g++, Unix socket libraries
 * 
 * This client establishes an encrypted connection with the server using:
 * 1. TCP socket connection (Unix socket API)
 * 2. Diffie-Hellman key exchange for secure key agreement
 * 3. XOR cipher encryption for all transmitted data
 * 
 * NOTE: This code will NOT compile on Windows due to Unix-specific includes
 */

#include <iostream>
#include <string>
// Unix-specific socket headers (NOT compatible with Windows)
#include <sys/socket.h>    // Unix socket API
#include <netinet/in.h>    // Unix network structures
#include <arpa/inet.h>     // Unix address conversion functions
#include <unistd.h>        // Unix system calls (close, etc.)
#include "common.h"        // Shared constants
#include "security.h"      // Encryption classes
using namespace std;

int main() {
    // Step 1: Create TCP socket for communication
    // AF_INET = IPv4, SOCK_STREAM = TCP protocol, 0 = default protocol
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    
    // Step 2: Configure server address structure
    sockaddr_in addr = {AF_INET, htons(SERVER_PORT)};  // htons converts port to network byte order
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");      // Connect to localhost (loopback address)
    
    // Step 3: Attempt to connect to the server
    if (connect(client_socket, (sockaddr*)&addr, sizeof(addr)) != 0) {
        cout << "Connection failed" << endl;
        return 1;
    }
    cout << "Connected to server" << endl;
    
    // Step 4: Initialize cryptographic objects
    DiffieHellman dh;    // For secure key exchange
    XORCipher cipher;    // For symmetric encryption using the shared secret
    
    // Step 5: DIFFIE-HELLMAN KEY EXCHANGE PROTOCOL
    // This allows both parties to agree on a shared secret without transmitting it
    
    // Generate our private/public key pair
    dh.generateKeys();
    
    // Receive server's public key first
    char buffer[BUFFER_SIZE];
    recv(client_socket, buffer, BUFFER_SIZE, 0);           // Blocking receive
    long long server_key = stoll(string(buffer));         // Convert received string to number
    
    // Send our public key to the server
    string my_key = to_string(dh.getPublicKey()) + "\n";  // Convert our key to string
    send(client_socket, my_key.c_str(), my_key.length(), 0);
    
    // Step 6: Calculate shared secret using server's public key and our private key
    // Both client and server will compute the same shared secret independently
    dh.computeSharedSecret(server_key);
    
    // Step 7: Initialize cipher with the shared secret
    // This secret will be used as the encryption key for all future communication
    cipher.setKey(dh.getSharedSecret());
    
    cout << "Encryption established. Enter commands (exit to quit):" << endl;
    
    // Step 8: SECURE COMMAND TRANSMISSION LOOP
    // All user input will be encrypted before transmission
    string command;
    while (getline(cin, command)) {
        if (command == "exit") break;  // Exit condition
        
        // Encrypt the command using XOR cipher with shared secret
        string encrypted = cipher.encrypt(command);
        
        // Convert encrypted binary data to hexadecimal for safe transmission
        // This prevents issues with null bytes and special characters in TCP stream
        string hex = cipher.toHex(encrypted);
        
        // Send encrypted command to server
        send(client_socket, hex.c_str(), hex.length(), 0);
        cout << "Sent: " << command << endl;
    }
    
    // Step 9: Clean up and close connection (Unix close() function)
    close(client_socket);
    return 0;
}