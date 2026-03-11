# Secure TCP Client-Server (Ubuntu/Linux ONLY)

**Platform Requirements:**
- Ubuntu/Linux operating system
- g++ compiler with C++11 support
- Unix socket libraries (included in Linux)

Implementation uses Diffie-Hellman key exchange + XOR encryption for secure TCP communication.

## System Requirements
```bash
# Install build tools on Ubuntu
sudo apt-get update
sudo apt-get install build-essential g++
```

## Files
- `common.h` - Shared constants and configuration
- `security.h` - Cryptographic function declarations  
- `security.cpp` - DH key exchange + XOR cipher implementation
- `client.cpp` - TCP client with encryption
- `server.cpp` - TCP server with decryption
- `Makefile` - Linux build configuration

## Build (Ubuntu/Linux)
```bash
make all
```

## Usage

**Start Server (Terminal 1):**
```bash
./server
```

**Start Client (Terminal 2):**
```bash
./client
```

Enter commands in client - they're encrypted and sent to server.
Server prints received decrypted commands.
Type `exit` to quit client.

## Security Protocol
1. TCP connection established on port 8080
2. Diffie-Hellman key exchange (prime: 2³¹-1, generator: 2)
3. All communication XOR encrypted using shared secret
4. Commands transmitted as hex-encoded encrypted data

## Technical Notes
- Uses Unix socket API (`sys/socket.h`, `netinet/in.h`, etc.)
- Requires Unix `close()` function for socket cleanup
- Build system uses Unix `rm` command
