#ifndef AGENT_CONFIG_H
#define AGENT_CONFIG_H

#include <string>
#include <vector>

// Communication protocol configuration
constexpr const char* AGENT_PROTOCOL = "https";
constexpr const char* AGENT_DOMAIN = "example.com";
constexpr int AGENT_PORT = 443;

// Logging configuration
constexpr char AGENT_LOG_LEVEL[] = "DEBUG";
constexpr char AGENT_LOG_FILE[] = "agent.log";
constexpr size_t AGENT_LOG_SIZE = 10 * 1024 * 1024; // 10MB

// Encryption configuration
constexpr char AGENT_ENCRYPTION_KEY[] = "my_secret_key";
constexpr char AGENT_ENCRYPTION_IV[] = "my_secret_iv";
constexpr int AGENT_ENCRYPTION_METHOD = 1; // 1 = AES-256-CBC, 2 = RSA-2048

// Obfuscation configuration
constexpr int AGENT_OBFUSCATION_LEVEL = 2; // 1 = light, 2 = medium, 3 = heavy
constexpr char AGENT_OBFUSCATION_KEY[] = "my_obfuscation_key";

// Anti-debugging configuration
constexpr bool AGENT_ANTI_DEBUGGING = true;
constexpr int AGENT_ANTI_DEBUGGING_METHOD = 1; // 1 = IsDebuggerPresent, 2 = CheckRemoteDebuggerPresent

// Process hollowing configuration
constexpr bool AGENT_PROCESS_HOLLOWING = true;
constexpr char AGENT_PROCESS_HOLLOWING_EXE[] = "notepad.exe";

// DLL injection configuration
constexpr bool AGENT_DLL_INJECTION = true;
constexpr char AGENT_DLL_INJECTION_DLL[] = "my_dll.dll";

// Network configuration
constexpr char AGENT_NETWORK_INTERFACE[] = "eth0";
constexpr int AGENT_NETWORK_PORT = 8080;

// Jittering configuration
constexpr bool AGENT_JITTERING = true;
constexpr int AGENT_JITTERING_INTERVAL = 1000; // 1 second
constexpr int AGENT_JITTERING_VARIANCE = 500; // 500ms

// Sleep configuration
constexpr bool AGENT_SLEEP = true;
constexpr int AGENT_SLEEP_INTERVAL = 60000; // 1 minute
constexpr int AGENT_SLEEP_VARIANCE = 30000; // 30 seconds

// Persistence configuration
constexpr bool AGENT_PERSISTENCE = true;
constexpr char AGENT_PERSISTENCE_REG_KEY[] = "HKCU\\Software\\MyCompany\\MyProduct";
constexpr char AGENT_PERSISTENCE_REG_VALUE[] = "MyValue";

// Evasion configuration
constexpr bool AGENT_EVASION = true;
constexpr int AGENT_EVASION_METHOD = 1; // 1 = code caves, 2 = process doppelganging

#endif // AGENT_CONFIG_H
