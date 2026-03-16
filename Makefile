# Makefile for Secure TCP Client-Server (Ubuntu/Linux ONLY)
# Requires: g++, Unix socket libraries
# Platform: Ubuntu/Linux (NOT compatible with Windows)

CXX = g++
CXXflags = -std=c++11 -O2 -Wall

# Build both client and server
all: client server

# Client executable
client: client.cpp security.cpp
	$(CXX) $(CXXFLAGS) -o client client.cpp security.cpp

# Server executable  
server: server.cpp security.cpp
	$(CXX) $(CXXFLAGS) -o server server.cpp security.cpp

# Clean build artifacts (Unix rm command)
clean:
	rm -f client server

# Install dependencies on Ubuntu (if needed)
install-deps:
	sudo apt-get update
	sudo apt-get install build-essential g++

.PHONY: all clean install-deps