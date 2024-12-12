#include <iostream>
#include <fstream>
#include <iomanip>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>
#include <ctime>
#include <sstream>
#include <stdexcept>
#include <ncurses.h>
#include <cstring>
#include <cstdlib>

// Constants for shellcode formats and obfuscation types
enum Format { BYTE_ARRAY = 1, HEX, BASE64, POWERSHELL, PYTHON };
enum Obfuscation { NONE = 1, BASE64_ENCODING, RANDOM_CODE_INSERTION, XOR_ENCRYPTION };

// Shellcode generator class definition
class ShellcodeGenerator {
public:
    ShellcodeGenerator();
    ~ShellcodeGenerator();
    void start();

private:
    void initUI();
    void cleanupUI();
    void showMainMenu();
    void showHelp();
    void displayError(const std::string& message);
    void displaySuccess(const std::string& message);
    void promptForFile(std::string& filePath);
    void promptForFormat(Format& format);
    void promptForObfuscation(Obfuscation& obfuscation);
    void applyObfuscation(std::ifstream& input, std::ofstream& output, Obfuscation obfuscation);
    void printByteArray(std::ifstream& input, std::ofstream& output);
    void printHex(std::ifstream& input, std::ofstream& output);
    void printBase64(std::ifstream& input, std::ofstream& output);
    void printPowershell(std::ifstream& input, std::ofstream& output);
    void printPython(std::ifstream& input, std::ofstream& output);
    void logActivity(const std::string& message);
    std::string getTimeStamp();
    void generateShellcode(const std::string& inputFile, const std::string& outputFile, Format format, Obfuscation obfuscation);
};

// Constructor - Setup ncurses UI
ShellcodeGenerator::ShellcodeGenerator() {
    initUI();
}

// Destructor - Cleanup ncurses UI
ShellcodeGenerator::~ShellcodeGenerator() {
    cleanupUI();
}

// Initialize ncurses UI
void ShellcodeGenerator::initUI() {
    initscr();              // Initialize ncurses
    raw();                  // Disable line buffering
    keypad(stdscr, TRUE);   // Enable special keys
    noecho();               // Disable automatic echoing of input
    start_color();          // Enable color support
    init_pair(1, COLOR_CYAN, COLOR_BLACK);  // Success message color
    init_pair(2, COLOR_WHITE, COLOR_BLUE);  // General text color
    init_pair(3, COLOR_RED, COLOR_BLACK);   // Error message color
    init_pair(4, COLOR_GREEN, COLOR_BLACK); // Info message color
}

// Cleanup ncurses UI
void ShellcodeGenerator::cleanupUI() {
    endwin();  // End ncurses mode
}

// Show main menu to the user
void ShellcodeGenerator::showMainMenu() {
    clear();
    attron(COLOR_PAIR(2));  // General text color
    printw("===== Metamorphic Shellcode Generator =====\n");
    printw("1. Convert EXE to Shellcode (Byte Array)\n");
    printw("2. Convert EXE to Hex\n");
    printw("3. Convert EXE to Base64\n");
    printw("4. Convert EXE to PowerShell Script\n");
    printw("5. Convert EXE to Python Script\n");
    printw("6. Exit\n");
    printw("7. Help\n");
    attroff(COLOR_PAIR(2));  // Reset color
    printw("Enter your choice: ");
}

// Show help menu to explain functionality
void ShellcodeGenerator::showHelp() {
    clear();
    attron(COLOR_PAIR(4));  // Info message color
    printw("Help Section:\n");
    printw("1. Convert EXE to Shellcode (Byte Array): Generate raw byte array shellcode.\n");
    printw("2. Convert EXE to Hex: Display the shellcode in hex format.\n");
    printw("3. Convert EXE to Base64: Display shellcode as Base64 encoded data.\n");
    printw("4. Convert EXE to PowerShell: Generates PowerShell code for execution.\n");
    printw("5. Convert EXE to Python: Generates Python script for execution.\n");
    printw("6. Exit: Exit the program.\n");
    printw("7. Help: Display this help screen.\n");
    printw("\nPress any key to return to the main menu.");
    attroff(COLOR_PAIR(4));  // Reset color
    getch();  // Wait for user to press a key
}

// Display error message with colored output
void ShellcodeGenerator::displayError(const std::string& message) {
    clear();
    attron(COLOR_PAIR(3));  // Error color
    printw("ERROR: %s\n", message.c_str());
    attroff(COLOR_PAIR(3));  // Reset color
    printw("\nPress any key to continue...");
    getch();
}

// Display success message with colored output
void ShellcodeGenerator::displaySuccess(const std::string& message) {
    clear();
    attron(COLOR_PAIR(1));  // Success color
    printw("SUCCESS: %s\n", message.c_str());
    attroff(COLOR_PAIR(1));  // Reset color
    printw("\nPress any key to continue...");
    getch();
}

// Prompt user for input file
void ShellcodeGenerator::promptForFile(std::string& filePath) {
    echo();
    printw("Enter EXE file path: ");
    scanw("%s", filePath.c_str());
    noecho();
}

// Prompt user for output format choice
void ShellcodeGenerator::promptForFormat(Format& format) {
    printw("Enter output format (1=Byte Array, 2=Hex, 3=Base64, 4=PowerShell, 5=Python): ");
    scanw("%d", &format);
}

// Prompt user for obfuscation method
void ShellcodeGenerator::promptForObfuscation(Obfuscation& obfuscation) {
    printw("Apply metamorphic obfuscation? (1=No, 2=Base64 encoding, 3=Random code insertion, 4=XOR encryption): ");
    scanw("%d", &obfuscation);
}

// Apply obfuscation (base64, random code insertion, XOR encryption)
void ShellcodeGenerator::applyObfuscation(std::ifstream& input, std::ofstream& output, Obfuscation obfuscation) {
    std::vector<unsigned char> buffer(1024);
    size_t bytesRead;

    switch (obfuscation) {
        case NONE:
            while (input.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
                output.write(reinterpret_cast<char*>(buffer.data()), input.gcount());
            }
            break;
        case BASE64_ENCODING:
            printBase64(input, output);
            break;
        case RANDOM_CODE_INSERTION:
            while (input.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
                // Random code insertion (example, adds some junk bytes)
                for (size_t i = 0; i < input.gcount(); i++) {
                    if (rand() % 5 == 0) buffer[i] = rand() % 256;
                }
                output.write(reinterpret_cast<char*>(buffer.data()), input.gcount());
            }
            break;
        case XOR_ENCRYPTION:
            while (input.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
                for (size_t i = 0; i < input.gcount(); i++) {
                    buffer[i] ^= 0xAA;  // Example XOR with 0xAA
                }
                output.write(reinterpret_cast<char*>(buffer.data()), input.gcount());
            }
            break;
        default:
            displayError("Invalid obfuscation choice.");
            break;
    }
}

// Print byte array shellcode format
void ShellcodeGenerator::printByteArray(std::ifstream& input, std::ofstream& output) {
    unsigned char byte;
    while (input.read(reinterpret_cast<char*>(&byte), 1)) {
        output << "0x" << std::setw(2) << std::setfill('0') << std::hex << (int)byte << ", ";
    }
}

// Print hex format
void ShellcodeGenerator::printHex(std::ifstream& input, std::ofstream& output) {
    unsigned char byte;
    while (input.read(reinterpret_cast<char*>(&byte), 1)) {
        output << std::setw(2) << std::setfill('0') << std::hex << (int)byte;
    }
}

// Print Base64 format
void ShellcodeGenerator::printBase64(std::ifstream& input, std::ofstream& output) {
    unsigned char byte;
    std::stringstream ss;
    while (input.read(reinterpret_cast<char*>(&byte), 1)) {
        ss << std::setw(2) << std::setfill('0') << std::hex << (int)byte;
    }
    std::string base64 = output
    output << base64;
}

// Print PowerShell format
void ShellcodeGenerator::printPowershell(std::ifstream& input, std::ofstream& output) {
    output << "$Shellcode = @('\n";
    unsigned char byte;
    while (input.read(reinterpret_cast<char*>(&byte), 1)) {
        output << "0x" << std::setw(2) << std::setfill('0') << std::hex << (int)byte << ", ";
    }
    output << ")\nInvoke-Expression ([System.Text.Encoding]::ASCII.GetString($Shellcode))\n";
}

// Print Python format
void ShellcodeGenerator::printPython(std::ifstream& input, std::ofstream& output) {
    output << "shellcode = b'\n";
    unsigned char byte;
    while (input.read(reinterpret_cast<char*>(&byte), 1)) {
        output << "\\x" << std::setw(2) << std::setfill('0') << std::hex << (int)byte;
    }
    output << "'\n# Add your shellcode execution code here\n";
}

// Log activity to a file
void ShellcodeGenerator::logActivity(const std::string& message) {
    std::ofstream logfile("activity_log.txt", std::ios::app);
    if (logfile) {
        logfile << getTimeStamp() << " - " << message << std::endl;
    }
}

// Get current timestamp
std::string ShellcodeGenerator::getTimeStamp() {
    std::time_t now = std::time(nullptr);
    std::tm* local_time = std::localtime(&now);
    std::stringstream ss;
    ss << std::put_time(local_time, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Main logic
void ShellcodeGenerator::generateShellcode(const std::string& inputFile, const std::string& outputFile, Format format, Obfuscation obfuscation) {
    try {
        std::ifstream input(inputFile, std::ios::binary);
        if (!input.is_open()) {
            displayError("Failed to open input file.");
            return;
        }

        std::ofstream output(outputFile, std::ios::binary);
        if (!output.is_open()) {
            displayError("Failed to open output file.");
            return;
        }

        applyObfuscation(input, output, obfuscation);

        switch (format) {
            case BYTE_ARRAY: printByteArray(input, output); break;
            case HEX: printHex(input, output); break;
            case BASE64: printBase64(input, output); break;
            case POWERSHELL: printPowershell(input, output); break;
            case PYTHON: printPython(input, output); break;
            default:
                displayError("Unknown shellcode format.");
                break;
        }

        logActivity("Shellcode generated successfully: " + outputFile);
        displaySuccess("Shellcode generated and saved to " + outputFile);
    } catch (const std::exception& e) {
        displayError("An error occurred: " + std::string(e.what()));
    }
}

int main() {
    ShellcodeGenerator generator;
    generator.start();
    return 0;
}
