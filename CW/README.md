# Secure TCP Client-Server (Simplified)

Diffie-Hellman key exchange + XOR encryption for TCP communication.

## Files
- `common.h` - Constants
- `security.h` - DH and XOR declarations  
- `security.cpp` - Crypto implementation
- `client.cpp` - Client (connects, shell)
- `server.cpp` - Server (listens, prints commands)

## Build
```bash
make all
```

## Usage

**Server:**
```bash
./server.exe
```

**Client:**
```bash
./client.exe
```

Enter commands in client - they're encrypted and sent to server.
Server prints received commands without executing them.
Type `exit` to quit client.

## Protocol
1. TCP connection on port 8080
2. DH key exchange (prime: 2³¹-1, generator: 2)
3. XOR encrypted communication
4. Commands sent as hex-encoded encrypted data