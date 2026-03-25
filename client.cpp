#include <iostream>
#include <string> 
#include <sys/socket.h>    // Unix socket API
#include <netinet/in.h>    // Unix network structures
#include <arpa/inet.h>     // Unix address conversion functions
#include <unistd.h>        // Unix system calls (close, etc.)
#include "common.h"        
#include "security.h"      
using namespace std;

bool recvLine(int socket_fd, string& out) {
    out.clear();
    char ch;

    while (true) {
        int n = recv(socket_fd, &ch, 1, 0);
        if (n <= 0) {
            return false;
        }
        if (ch == '\n') {
            return true;
        }
        out.push_back(ch);

        if (out.size() > static_cast<size_t>(BUFFER_SIZE * 4)) {
            return false;
        }
    }
}

int main() {
    //Create TCP socket for communication
    //IPv4, SOCK_STREAM = TCP protocol
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    
    //Configure server address structure
    sockaddr_in addr = {AF_INET, htons(SERVER_PORT)};  //Converts port to network byte order
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
    string server_key_line;
    if (!recvLine(client_socket, server_key_line)) {
        cout << "Failed to receive server key" << endl;
        close(client_socket);
        return 1;
    }
    long long server_key = stoll(server_key_line);
    
    // Send public key to the server
    string my_key = to_string(dh.getPublicKey()) + "\n";  
    send(client_socket, my_key.c_str(), my_key.length(), 0);
    
    //Calculate shared secret using server's public key and our private key
    dh.computeSharedSecret(server_key);
    
    //Initialize cipher with the shared secret
    cipher.setKey(dh.getSharedSecret());
    
    bool logged_in = false;
    while (!logged_in){
        string username, password;
        cout << "Username: ";
        getline(cin, username);
        cout << "Password: ";
        getline(cin, password);

        string login = username + ":" + password;
        string encrypted = cipher.encrypt(login);
        string hex = cipher.toHex(encrypted);
        string framed = hex + "\n";
        send(client_socket, framed.c_str(), framed.length(), 0);

        string response_hex;
        if (!recvLine(client_socket, response_hex)) {
            cout << "Disconnected during login" << endl;
            close(client_socket);
            return 1;
        }
        string decrypted_response = cipher.encrypt(cipher.fromHex(response_hex));

        if (decrypted_response == "AUTH_SUCCESS\n") {
            cout << "Login successful!" << endl;
            logged_in = true;
        } else {
            cout << "Login failed. Try again." << endl;
        }
    }
    
    //SECURE COMMAND LOOP
    string command;
    while (getline(cin, command)) {
        if (command == "exit") break;
        
        // Encrypt the command using XOR cipher with shared secret
        string encrypted = cipher.encrypt(command);
        
        // Convert encrypted binary data to hexadecimal
        string hex = cipher.toHex(encrypted);
        
        // Send encrypted command to server
        string framed = hex + "\n";
        send(client_socket, framed.c_str(), framed.length(), 0);

        string reply_hex;
        if (!recvLine(client_socket, reply_hex)) {
            cout << "Disconnected from server" << endl;
            break;
        }
        string reply = cipher.encrypt(cipher.fromHex(reply_hex));
        cout << "Server: " << reply;
    }
    
    //Clean up and close connection
    close(client_socket);
    return 0;
}