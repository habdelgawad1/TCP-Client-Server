CXX = g++
CXXFLAGS = -std=c++11 -O2

all: client server

client: client.cpp security.cpp
	$(CXX) $(CXXFLAGS) -o client client.cpp security.cpp

server: server.cpp security.cpp
	$(CXX) $(CXXFLAGS) -o server server.cpp security.cpp

clean:
	rm -f client server

.PHONY: all clean