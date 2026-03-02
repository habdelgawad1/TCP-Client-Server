CXX = g++
CXXFLAGS = -std=c++11 -O2
LIBS = -lws2_32

all: client.exe server.exe

client.exe: client.cpp security.cpp
	$(CXX) $(CXXFLAGS) -o client.exe client.cpp security.cpp $(LIBS)

server.exe: server.cpp security.cpp
	$(CXX) $(CXXFLAGS) -o server.exe server.cpp security.cpp $(LIBS)

clean:
	del /f client.exe server.exe 2>nul || true

.PHONY: all clean