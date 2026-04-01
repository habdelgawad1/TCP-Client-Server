# Makefile for Secure TCP Client-Server (Ubuntu/Linux ONLY)
# Requires: g++, Unix socket libraries
# Platform: Ubuntu/Linux (NOT compatible with Windows)

CXX = g++
CXXFLAGS = -std=c++11 -O2 -Wall -pthread
LDFLAGS = -lssl -lcrypto

# Build both client and server
all: client server

# Client executable
client: client.cpp security.cpp
	$(CXX) $(CXXFLAGS) -o client client.cpp security.cpp $(LDFLAGS)

# Server executable  
server: server.cpp security.cpp
	$(CXX) $(CXXFLAGS) -o server server.cpp security.cpp $(LDFLAGS)

# Clean build artifacts (Unix rm command)
clean:
	rm -f client server

# Install dependencies on Ubuntu (if needed)
install-deps:
	sudo apt-get update
	sudo apt-get install build-essential g++ libssl-dev

.PHONY: all clean install-deps