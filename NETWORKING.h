#ifndef NETWORKING_H
#define NETWORKING_H

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <string>

// Enum for network protocols
enum class NetworkProtocol { TCP, UDP, HTTPS };

// Enum for C2 communication types
enum class C2Type { HEARTBEAT, COMMAND, RESPONSE };

// Structure for C2 messages
struct C2Message {
    C2Type type;
    std::string data;
};

// Structure for network configuration
struct NetworkConfig {
    NetworkProtocol protocol;
    std::string serverIP;
    int serverPort;
    int timeout;
};

// Function prototypes
void initNetwork(const NetworkConfig& config);
void sendC2Message(const C2Message& message);
C2Message receiveC2Message();
void closeNetwork();

#endif // NETWORKING_H