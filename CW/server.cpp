/**
 * SERVER.CPP - Secure TCP Server Implementation
 * 
 * PLATFORM: Ubuntu/Linux ONLY (Uses Unix socket API)
 * DEPENDENCIES: g++, Unix socket libraries
 * 
 * This server accepts encrypted connections from clients using:
 * 1. TCP socket binding and listening (Unix socket API)
 * 2. Diffie-Hellman key exchange for secure key agreement
 * 3. XOR cipher decryption for all received data
 * 4. Command reception and processing (currently just displays commands)
 * 
 * NOTE: This code will NOT compile on Windows due to Unix-specific includes
 */

#include <iostream>
#include <string>
// Unix-specific socket headers (NOT compatible with Windows)
#include <sys/socket.h>    // Unix socket API
#include <netinet/in.h>    // Unix network structures  
#include <arpa/inet.h>     // Unix address conversion
#include <unistd.h>        // Unix system calls (close, etc.)
#include "common.h"        // Shared constants
#include "security.h"      // Encryption classes
using namespace std;

int main() {
    // Step 1: Create server socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    
    // Step 2: Configure server address to bind to
    // INADDR_ANY means accept connections on any network interface
    sockaddr_in addr = {AF_INET, htons(SERVER_PORT), {INADDR_ANY}};
    
    // Step 3: Bind socket to the specified port and start listening
    bind(server_socket, (sockaddr*)&addr, sizeof(addr));
    listen(server_socket, 1);  // Queue up to 1 pending connection
    cout << "Server listening on port " << SERVER_PORT << endl;
    
    // Step 4: MAIN SERVER LOOP - Handle multiple clients sequentially
    while (true) {
        // Wait for and accept a client connection (blocking call)
        int client = accept(server_socket, 0, 0);
        cout << "Client connected" << endl;
        
        // Step 5: Initialize cryptographic objects for this client
        DiffieHellman dh;    // Fresh key exchange for each client
        XORCipher cipher;    // Cipher using the agreed shared secret
        
        // Step 6: DIFFIE-HELLMAN KEY EXCHANGE (Server Side)
        // Generate our key pair for this session
        dh.generateKeys();
        
        // Send our public key to client first
        string my_key = to_string(dh.getPublicKey()) + "\n";
        send(client, my_key.c_str(), my_key.length(), 0);
        
        // Receive client's public key
        char buffer[BUFFER_SIZE];
        recv(client, buffer, BUFFER_SIZE, 0);
        long long client_key = stoll(string(buffer));
        
        // Step 7: Compute shared secret and initialize cipher
        // The same secret computed by client: (client_public^server_private) mod p
        dh.computeSharedSecret(client_key);
        cipher.setKey(dh.getSharedSecret());
        
        // Step 8: SECURE COMMAND RECEPTION LOOP
        // Continuously receive and decrypt commands from this client
        while (true) {
            int len = recv(client, buffer, BUFFER_SIZE, 0);
            if (len <= 0) break;  // Client disconnected or error
            
            // Null-terminate the received data
            buffer[len] = 0;
            
            // Step 9: DECRYPTION PROCESS
            string hex(buffer);                           // Received hex-encoded data
            string encrypted = cipher.fromHex(hex);       // Convert hex back to binary
            string command = cipher.encrypt(encrypted);   // XOR "decrypt" (XOR is symmetric)
            
            cout << "Command: " << command << endl;
            
            // NOTE: In a real implementation, you would parse and execute the command here
            // For security, commands should be validated before execution
        }
        
        // Step 10: Clean up client connection (Unix close() function)
        close(client);
        cout << "Client disconnected" << endl;
    }
    
    // Clean up server socket (Unix close() function)
    close(server_socket);
    return 0;
}