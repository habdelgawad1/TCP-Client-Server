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
#include <cstdlib>      // For system() command execution
#include <cstdio>       // For popen/pclose command output capture    
using namespace std;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

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

        // Guard against malformed or unbounded payloads.
        if (out.size() > static_cast<size_t>(BUFFER_SIZE * 4)) {
            return false;
        }
    }
}

vector<User> loadUsers() {
    vector<User> users;
    ifstream file("users.txt");
    string line;
    while (getline(file,line)){
        stringstream ss(line);
        string username, password, level_str;
        if (getline(ss, username, ':') && getline(ss, password, ':') && getline(ss, level_str, ':')){
            AccessLevel level = static_cast<AccessLevel>(stoi(level_str));
            users.push_back({username, password, level});
        }
    }
    return users;
}

void* handle_client(void* arg){
    int client = (intptr_t)arg;

    DiffieHellman dh;
    AESCipher cipher;

    // Diffie-Hellman Key Exchange
    dh.generateKeys();

    // Send public key and authentication HMAC to client
    string my_key = to_string(dh.getPublicKey());
    string hmac = computeHMAC(my_key, dh.getPublicKey());
    string auth_msg = my_key + ":" + hmac + "\n";
    send(client, auth_msg.c_str(), auth_msg.length(), 0);

    // Receive client's public key
    string client_key_line;
    if (!recvLine(client, client_key_line)) {
        close(client);
        return nullptr;
    }
    dh.computeSharedSecret(stoll(client_key_line));

    cipher.setKey(dh.getSharedSecret());

    vector<User> users = loadUsers();
    int current_level = -1;

    while (current_level == -1){
        string auth_hex;
        if (!recvLine(client, auth_hex)) {
            close(client);
            return nullptr;
        }

        string decrypted = cipher.encrypt(cipher.fromHex(auth_hex));

        size_t delimiter = decrypted.find(":");
        if (delimiter != string::npos){
            string username = decrypted.substr(0, delimiter);
            string password = decrypted.substr(delimiter + 1);
            for (auto& user : users){
                if (username == user.username && password == user.password){
                    current_level = user.level;
                    break;
                }
            }
        }
        string response = (current_level != -1) ? "AUTH_SUCCESS\n" : "AUTH_FAIL\n";
        string encrypted_response = cipher.toHex(cipher.encrypt(response)) + "\n";
        send(client, encrypted_response.c_str(), encrypted_response.length(), 0);
    }

    // Secure Command Reception Loop
    while (true) {
        string hex;
        if (!recvLine(client, hex)) break;

        string encrypted = cipher.fromHex(hex);
        string command = cipher.decrypt(encrypted);
        
        if (!isCommandAllowed(current_level, command)) {
            string msg = cipher.toHex(cipher.encrypt("Access Denied: Level Insufficient\n")) + "\n";
            send(client, msg.c_str(), msg.length(), 0);
            continue;
        }

        //Lock mutex and execute command, capturing output
        pthread_mutex_lock(&mutex);
        cout << "[Thread " << pthread_self() << "] Executing: " << command << endl;
        
        string output;
        FILE* pipe = popen(command.c_str(), "r");
        if (pipe) {
            char buffer[128];
            while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                output += buffer;
            }
            pclose(pipe);
        }
        pthread_mutex_unlock(&mutex);

        // Send command output back to client
        if (output.empty()) {
            output = "OK\n";
        }
        string reply = cipher.toHex(cipher.encrypt(output)) + "\n";
        send(client, reply.c_str(), reply.length(), 0);

    }

    // Clean up client connection
    close(client);
    return nullptr;
}

int main() {
    // Create server socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    
    // Configure server address structure
    sockaddr_in addr = {AF_INET, htons(SERVER_PORT), {INADDR_ANY}};
    
    // Bind socket to the specified port and start listening
    bind(server_socket, (sockaddr*)&addr, sizeof(addr));
    listen(server_socket, 8);
    cout << "Server Listening On Port " << SERVER_PORT << endl;
    
    // Main Server Loop
    while (true) {
        int client = accept(server_socket, 0, 0);
        cout << "Client Connected" << endl;
        
        pthread_t thread_id;
        pthread_create(&thread_id, nullptr, handle_client, (void*)(intptr_t)client);
        // Detach thread to allow independent execution
        pthread_detach(thread_id);
    }
}