# Secure Remote Command Execution System

A multi-threaded, encrypted TCP client-server system for executing Linux commands remotely with role-based access control. Uses Diffie-Hellman key exchange, AES-256-CBC encryption, and HMAC-SHA256 authentication for secure communication.

**Platform:** Ubuntu/Linux only

## Features

✅ **Secure Communication**
- Diffie-Hellman key exchange for secure key negotiation
- AES-256-CBC symmetric encryption for all data transmission
- HMAC-SHA256 for server authentication and integrity verification
- Hex encoding for safe TCP transmission of binary data

✅ **Authentication & Authorization**
- User credential validation from `users.txt`
- Three access levels: GUEST, USER, ADMIN
- Role-based command execution restrictions

✅ **Multi-Client Support**
- Threaded server architecture (one thread per client)
- Mutex-protected shared resources
- Concurrent command execution with thread-safe logging

✅ **Remote Command Execution**
- Commands executed on server with full output capture
- Output encrypted and returned to client
- Access control enforced before execution

## System Requirements
```bash
# Install build tools and OpenSSL libraries on Ubuntu/Linux
sudo apt-get update
sudo apt-get install build-essential g++ make libssl-dev
```

## Project Structure

### Core Files
- **`common.h`** - Shared constants (port, buffer size, DH parameters, access levels)
- **`security.h`** - Cryptographic class declarations
- **`security.cpp`** - DH key exchange + AES encryption implementation
  - `DiffieHellman` class: Key generation, shared secret computation
  - `AESCipher` class: AES-256-CBC encryption/decryption, hex encoding/decoding
  - `computeHMAC()`: HMAC-SHA256 signature generation for server authentication
  - `isCommandAllowed()`: Access control enforcement

### Application Files
- **`client.cpp`** - TCP client application
  - Connects to server at `127.0.0.1:8080`
  - Performs DH key exchange
  - Prompts for login credentials
  - Sends encrypted commands and displays results
  
- **`server.cpp`** - Multi-threaded TCP server
  - Listens on port 8080
  - Accepts client connections in separate threads
  - Executes authenticated commands via `popen()`
  - Returns captured output to client

- **`Makefile`** - Linux build configuration
- **`README.md`** - This documentation file
- **`users.txt`** - User credentials database (format: `username:password:level`)

## Build

```bash
# Compile all components
make all

# By individual targets
make server
make client
make clean
```

## Running the System

### Terminal 1 - Start Server
```bash
./server
# Output: Server Listening On Port 8080
```

### Terminal 2+ - Start Client(s)
```bash
./client
# Output: Connected To Server
# Prompt: Username: 
# Prompt: Password:
```

## User Authentication & Roles

### Login
1. Client connects and performs DH key exchange
2. Client sends encrypted `username:password`
3. Server validates against `users.txt`
4. User assigned access level (0=GUEST, 1=USER, 2=ADMIN)

### Access Levels

**GUEST (Level 0)** - Read-only operations
```
ls, cat, pwd, head, tail, grep, file
```

**USER (Level 1)** - Read, create, copy, modify
```
ls, cat, cp, mv, touch, mkdir, pwd, grep, find, echo
(Cannot delete files/directories)
```

**ADMIN (Level 2)** - Full Linux command access
```
All Linux commands allowed
(No restrictions)
```

## Command Execution Flow

1. Client sends encrypted command
2. Server decrypts using shared secret
3. Server checks if user role allows command
   - If denied → return "Access Denied" error
   - If allowed → proceed to execution
4. Server executes command via `popen()`
5. All output is captured (stdout)
6. Output is encrypted and returned to client
7. Client decrypts and displays result

## Example Workflow

### GUEST User - Read Only
```bash
Login: guest / guestpass
Input:  cat /etc/hostname
Output: myserver
Input:  mkdir newdir
Output: Access Denied: Level Insufficient
```

### USER - Create & Modify Files
```bash
Login: user / userpass
Input:  mkdir projects
Output: OK
Input:  touch projects/file.txt
Output: OK
Input:  ls projects
Output: file.txt
Input:  rm projects/file.txt
Output: Access Denied: Level Insufficient
```

### ADMIN - Full Control
```bash
Login: admin / adminpass
Input:  rm -rf sensitive_data
Output: OK
Input:  useradd newuser
Output: (command output)
```

## Security Details

### Diffie-Hellman Parameters
```c
Prime (p):     2147483647 (2^31 - 1, Mersenne prime)
Generator (g): 2
Key Size:      ~31 bits
```

### Encryption Method
- **Type:** Symmetric AES-256-CBC cipher (industry standard)
- **Key Derivation:** SHA256(shared_secret) → 256-bit key
- **Block Mode:** Cipher Block Chaining (CBC) with PKCS7 padding
- **Server Authentication:** HMAC-SHA256(server_public_key, shared_secret)

### Security Features
- Secure key exchange via Diffie-Hellman prevents eavesdropping on keys
- All commands and output encrypted with AES-256-CBC in transit
- Server authenticated using HMAC-SHA256 (prevents man-in-the-middle attacks)
- Hex encoding prevents binary data corruption in TCP stream
- No plaintext credentials sent
- Access control prevents unauthorized command execution

## Technical Implementation

### Multi-Threading
- Main server thread accepts connections
- Each client handled by dedicated thread
- All threads share `pthread_mutex_t` for synchronization
- Thread-safe command execution and logging

### Command Execution
- Uses `popen()` to execute shell commands and capture output
- Reads output line-by-line into buffer
- Max output size limited by TCP buffer constraints
- No interactive commands supported (nano, vi, vim)

### Network Protocol
```
1. TCP connection established
2. Server sends DH public key (newline-terminated)
3. Client sends DH public key (newline-terminated)
4. Both compute shared secret
5. Client sends encrypted credentials: username:password (hex format)
6. Server validates and sends: AUTH_SUCCESS or AUTH_FAIL
7. Command loop:
   - Client: encrypted command (hex format)
   - Server: encrypted output or error (hex format)
```

## Limitations & Notes

### Not Supported
- Interactive commands (nano, vi, vim, less, more)
- GUI applications
- Long-running background processes
- Real-time command streams

### Design Choices
- Simple XOR cipher for educational purposes (not production security)
- Stateless authentication per connection
- Single command execution per round-trip
- No command history or logging

## Users File Format

File: `users.txt`
```
admin:adminpass:2
user:userpass:1
guest:guestpass:0
```

Fields:
- **username** - Login identifier
- **password** - Plain text (store securely in production)
- **level** - Access level (0=GUEST, 1=USER, 2=ADMIN)

## Troubleshooting

### Connection Refused
```
Error: Connection Failed
Solution: Ensure server is running (./server in another terminal)
```

### Authentication Failed
```
Output: Login Failed. Try again.
Solution: Check credentials in users.txt match exactly (case-sensitive)
```

### Command Not Found
```
Output: Access Denied: Level Insufficient
Solution: Your user role doesn't permit this command. Check access table above.
```

### Build Errors
```
g++: command not found
Solution: Install build tools (sudo apt-get install build-essential g++)
```

## Files Reference

| File | Purpose | Language |
|------|---------|----------|
| common.h | Shared constants & enums | C++ Header |
| security.h | Crypto class declarations | C++ Header |
| security.cpp | DH + XOR cipher implementation | C++ |
| client.cpp | Client application | C++ |
| server.cpp | Server application | C++ |
| Makefile | Build automation | Make |
| users.txt | Credential database | Text |
| README.md | Documentation | Markdown |
