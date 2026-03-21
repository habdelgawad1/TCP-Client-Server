#include <iostream>
#include <string>
#include <pthread.h>       // Threads
#include <sys/socket.h>    // Unix socket API
#include <netinet/in.h>    // Unix network structures  
#include <arpa/inet.h>     // Unix address conversion
#include <unistd.h>        // Unix system calls (close, etc.)
#include "common.h"        
#include "security.h"  
#include <sstream>      // For string stream operations
#include <fstream>       // For file I/O
#include <vector>      // For user list    
using namespace std;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

vector<User> loadUsers() {
    vector<User> users;
    ifstream file("users.txt");
    string line;
    while (getline(file,line)){
        stringstream ss(line);
        string username, password, level;
        if (getline(ss, username, ":") && getline(ss, password, ":") && getline(ss,level, ":")){
            AccessLevel level = (AccessLevel)stoi(level);
            users.push_back({username, password, level});
        }
    }
    return users;
}

void* handle_client(void* arg){
    int client = (intptr_t)arg;

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
    dh.computeSharedSecret(stoll(string(buffer)));
    cipher.setKey(dh.getSharedSecret());

    vector<User> users = loadUsers();
    int current_level = -1;
    char auth_buffer[BUFFER_SIZE];

    while (current_level == -1){
        int len = recv(client, auth_buffer, BUFFER_SIZE, 0);
        if (len <= 0){
            return nullptr;
        }
        auth_buffer[len] = 0;
        string decrypted = cipher.encrypt(cipher.fromHex(string(auth_buffer)));
        size_t delimiter = decrypted.find(":");
        if (delimiter != string::npos){
            string username = decrypted.substr(0, delimiter);
            string password = decrypted.substr(delimiter + 1);
            for (auto& user : users){
                if (user==user.username && password == user.password){
                    current_level = user.level;
                    break;
                }
            }
        }
        string response = (current_level != -1) ? "AUTH_SUCCESS\n" : "AUTH_FAIL\n";
        string encrypted_response = cipher.toHex(cipher.encrypt(response));
        send(client, encrypted_response.c_str(), encrypted_response.length(), 0);
    }

    // Secure Command Reception Loop
    while (true) {
        int len = recv(client, buffer, BUFFER_SIZE, 0);
        if (len <= 0) break; 

        // Null-terminate the received data
        buffer[len] = 0;

        string hex(buffer);                           
        string encrypted = cipher.fromHex(hex);       
        string command = cipher.encrypt(encrypted);  
        
        if (!cipher.isCommandAllowed(current_level, command)) {
            string msg = cipher.toHex(cipher.encrypt("Access Denied: Level Insufficient\n"));
            send(client, msg.c_str(), msg.length(), 0);
            continue;

        //Lock mutex to safely print command
        pthread_mutex_lock(&mutex);
        cout << "[Thread " << pthread_self() << "]" "Command: " << command << endl;
        pthread_mutex_unlock(&mutex);

    }

    // Clean up client connection
    close(client);
    return nullptr;
}}

int main() {
    // Create server socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    
    // Configure server address structure
    sockaddr_in addr = {AF_INET, htons(SERVER_PORT), {INADDR_ANY}};
    
    // Bind socket to the specified port and start listening
    bind(server_socket, (sockaddr*)&addr, sizeof(addr));
    listen(server_socket, 1);
    cout << "Server listening on port " << SERVER_PORT << endl;
    
    // Main Server Loop
    while (true) {
        int client = accept(server_socket, 0, 0);
        cout << "Client connected" << endl;
        
        pthread_t thread_id;
        pthread_create(&thread_id, nullptr, handle_client, (void*)(intptr_t)client);
        // Detach thread to allow independent execution
        pthread_detach(thread_id);
    }
}