// COMMON.H - Shared Constants and Configuration
#ifndef COMMON_H
#define COMMON_H

const int SERVER_PORT = 8080;         // TCP port for server to listen on
const int BUFFER_SIZE = 1024;          // Maximum size for network message buffers
const long long DH_PRIME = 2147483647LL;     // Large prime p = 2^31 - 1 (Mersenne prime)
const long long DH_GENERATOR = 2;            // Generator g (primitive root modulo p)

#endif