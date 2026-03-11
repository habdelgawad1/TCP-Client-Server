/**
 * COMMON.H - Shared Constants and Configuration
 * 
 * This header contains configuration constants used by both
 * client and server for network communication and cryptography.
 */

#ifndef COMMON_H
#define COMMON_H

// Network Configuration
const int SERVER_PORT = 8080;         // TCP port for server to listen on
const int BUFFER_SIZE = 1024;          // Maximum size for network message buffers

// Diffie-Hellman Parameters
// These must be the same for both client and server
const long long DH_PRIME = 2147483647LL;     // Large prime p = 2^31 - 1 (Mersenne prime)
const long long DH_GENERATOR = 2;            // Generator g (primitive root modulo p)

// Security Notes:
// - DH_PRIME is a Mersenne prime (2^31 - 1), which is mathematically well-studied
// - DH_GENERATOR = 2 is a commonly used generator for this prime
// - These parameters provide reasonable security for educational purposes
// - Production systems should use much larger primes (2048+ bits)

#endif // COMMON_H