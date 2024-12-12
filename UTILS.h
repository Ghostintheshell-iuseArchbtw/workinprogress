#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include <windows.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

// Encryption namespace
namespace Encryption {
    std::string encryptData(const std::string& data, const std::string& key);
    std::string decryptData(const std::string& data, const std::string& key);
}

// File namespace
namespace File {
    bool create(const std::string& path);
    bool remove(const std::string& path);
    bool write(const std::string& path, const std::string& data);
    std::string read(const std::string& path);
}

// Directory namespace
namespace Directory {
    bool create(const std::string& path);
    bool remove(const std::string& path);
}

// System namespace
namespace System {
    std::string executeCommand(const std::string& command);
    std::string getCurrentTime();
    DWORD getCurrentProcessId();
    DWORD getCurrentThreadId();
    void sleepFor(DWORD milliseconds);
    bool isDebuggerPresent();
}

// Miscellaneous namespace
namespace Misc {
    std::string generateRandomString(size_t length);
}

#endif // UTILS_H
utils.cpp
C++
#include "utils.h"
#include <iostream>

// Encryption namespace
namespace Encryption {
    std::string encryptData(const std::string& data, const std::string& key) {
        try {
            AES_KEY aesKey;
            AES_set_encrypt_key((const unsigned char*)key.c_str(), 256, &aesKey);

            unsigned char* encryptedData = new unsigned char[data.size()];
            AES_encrypt((const unsigned char*)data.c_str(), encryptedData, &aesKey);

            std::string encryptedString((const char*)encryptedData, data.size());
            delete[] encryptedData;

            return encryptedString;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return "";
        }
    }

    std::string decryptData(const std::string& data, const std::string& key) {
        try {
            AES_KEY aesKey;
            AES_set_decrypt_key((const unsigned char*)key.c_str(), 256, &aesKey);

            unsigned char* decryptedData = new unsigned char[data.size()];
            AES_decrypt((const unsigned char*)data.c_str(), decryptedData, &aesKey);

            std::string decryptedString((const char*)decryptedData, data.size());
            delete[] decryptedData;

            return decryptedString;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return "";
        }
    }
}

// File namespace
namespace File {
    bool create(const std::string& path) {
        try {
            std::ofstream file(path);
            return file.is_open();
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return false;
        }
    }

    bool remove(const std::string& path) {
        try {
            return DeleteFile(path.c_str()) != 0;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return false;
        }
    }

    bool write(const std::string& path, const std::string& data) {
        try {
            std::ofstream file(path);
            if (file.is_open()) {
                file << data;
                file.close();
                return true;
            }
            return false;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return false;
        }
    }

    std::string read(const std::string& path) {
        try {
            std::ifstream file(path);
            if (file.is_open()) {
                std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                return data;
            }
            return "";
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return "";
        }
    }
}

// Directory namespace
namespace Directory {
    bool create(const std::string& path) {
        try {
            return CreateDirectory(path.c_str(), NULL) != 0;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return false;
        }
    }

    bool remove(const std::string& path) {
        try {
            return RemoveDirectory(path.c_str()) != 0;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return false;
        }
    }
}

// System namespace
namespace System {
    std::string executeCommand(const std::string& command) {
        try {
            std::string output;
            FILE* pipe = _popen(command.c_str(), "r");
            if (pipe) {
                char buffer[128];
                while (fgets(buffer, 128, pipe)) {
                    output += buffer;
                }
                _pclose(pipe);
            }
            return output;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return "";
        }
    }

    std::string getCurrentTime() {
        try {
            time_t currentTime = time(0);
            tm* localTime = localtime(&currentTime);
            char timeString[20];
            strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", localTime);
            return std::string(timeString);
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return "";
        }
    }

    DWORD getCurrentProcessId() {
        try {
            return GetCurrentProcessId();
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 0;
        }
    }

    DWORD getCurrentThreadId() {
        try {
            return GetCurrentThreadId();
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 0;
        }
    }

    void sleepFor(DWORD milliseconds) {
        try {
            Sleep(milliseconds);
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }

    bool isDebuggerPresent() {
        try {
            return IsDebuggerPresent() != 0;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return false;
        }
    }
}

// Miscellaneous namespace
namespace Misc {
    std::string generateRandomString(size_t length) {
        try {
            static const std::string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            std::string randomString;

            // Use secure random number generator
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, characters.size() - 1);

            for (size_t i = 0; i < length; ++i) {
                randomString += characters[dis(gen)];
            }

            return randomString;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return "";
        }
    }
}
