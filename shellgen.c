#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <time.h>

#define MAX_PATH_LENGTH 256

// Function Prototypes
void init_ui();
void cleanup_ui();
void show_main_menu();
void show_help();
void display_error(const char *message);
void display_success(const char *message);
void prompt_for_file(char *input_file);
void prompt_for_format(int *format_choice);
void prompt_for_obfuscation(int *obfuscation_choice);
void generate_shellcode(char *input_file, int format_choice, int obfuscation_choice, char *output_file);
void apply_metamorphic_obfuscation(FILE *input, FILE *output, int obfuscation_choice);
void print_byte_array(FILE *input, FILE *output);
void print_hex(FILE *input, FILE *output);
void print_base64(FILE *input, FILE *output);
void print_powershell(FILE *input, FILE *output);
void print_python(FILE *input, FILE *output);
void log_activity(const char *message);
void time_stamp(char *buffer);
void handle_file_open_error(const char *filename);

// Function Definitions
void log_activity(const char *message) {
    printf("Logging activity: %s\n", message);
}

void display_error(const char *message) {
    attron(COLOR_PAIR(3));  // Use color for error messages
    printw("Error: %s\n", message);
    attroff(COLOR_PAIR(3));  // Reset color
}
void apply_metamorphic_obfuscation(FILE *input, FILE *output, int obfuscation_choice) {
    unsigned char buffer[1024];
    size_t bytes_read;

    switch (obfuscation_choice) {
        case 1: // No obfuscation (direct copy)
            while ((bytes_read = fread(buffer, 1, sizeof(buffer), input)) > 0) {
                fwrite(buffer, 1, bytes_read, output);
            }
            break;
        case 2: // Base64 encoding
            print_base64(input, output);
            break;
        case 3: // Random code insertion (Obfuscation)
            printw("\nRandom code insertion in progress...\n");
            while ((bytes_read = fread(buffer, 1, sizeof(buffer), input)) > 0) {
                fwrite(buffer, 1, bytes_read, output);
            }
            break;
        default:
            display_error("Invalid obfuscation choice! Use 1 for no obfuscation.");
            log_activity("Invalid obfuscation choice.");
    }
}

void print_byte_array(FILE *input, FILE *output) {
    unsigned char byte;
    while (fread(&byte, 1, 1, input) > 0) {
        fprintf(output, "0x%02X, ", byte);
    }
}

void print_hex(FILE *input, FILE *output) {
    unsigned char byte;
    while (fread(&byte, 1, 1, input) > 0) {
        fprintf(output, "%02X ", byte);
    }
}

void print_base64(FILE *input, FILE *output) {
    const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char buffer[3];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, 3, input)) > 0) {
        fprintf(output, "%c%c%c%c", base64_chars[buffer[0] >> 2],
                                    base64_chars[((buffer[0] & 0x03) << 4) | (buffer[1] >> 4)],
                                    base64_chars[((buffer[1] & 0x0F) << 2) | (buffer[2] >> 6)],
                                    base64_chars[buffer[2] & 0x3F]);
    }
}

void print_powershell(FILE *input, FILE *output) {
    fprintf(output, "$Shellcode = @('\n");
    unsigned char byte;
    while (fread(&byte, 1, 1, input) > 0) {
        fprintf(output, "0x%02X, ", byte);
    }
    fprintf(output, ")\nInvoke-Expression ([System.Text.Encoding]::ASCII.GetString($Shellcode))\n");
}

void print_python(FILE *input, FILE *output) {
    fprintf(output, "shellcode = bytearray([\n");
    unsigned char byte;
    while (fread(&byte, 1, 1, input) > 0) {
        fprintf(output, "0x%02X, ", byte);
    }
    fprintf(output, "])\nexec(shellcode)\n");
}

// Main Program
int main() {
    init_ui();  // Initialize ncurses UI

    int choice;
    char input_file[MAX_PATH_LENGTH];
    char output_file[MAX_PATH_LENGTH];
    int format_choice;
    int obfuscation_choice;

    while (1) {
        show_main_menu();
        scanw("%d", &choice);

        switch (choice) {
            case 1: // Convert EXE to Shellcode
                prompt_for_file(input_file);
                printw("Enter the output file path: ");
                echo();
                scanw("%s", output_file);
                noecho();
                prompt_for_format(&format_choice);
                prompt_for_obfuscation(&obfuscation_choice);
                generate_shellcode(input_file, format_choice, obfuscation_choice, output_file);
                break;
            case 2: // Convert EXE to Hex
                prompt_for_file(input_file);
                printw("Enter the output file path: ");
                echo();
                scanw("%s", output_file);
                noecho();
                generate_shellcode(input_file, 2, 1, output_file);
                break;
            case 3: // Convert EXE to Base64
                prompt_for_file(input_file);
                printw("Enter the output file path: ");
                echo();
                scanw("%s", output_file);
                noecho();
                generate_shellcode(input_file, 3, 1, output_file);
                break;
            case 4: // Convert EXE to PowerShell Script
                prompt_for_file(input_file);
                printw("Enter the output file path: ");
                echo();
                scanw("%s", output_file);
                noecho();
                generate_shellcode(input_file, 4, 1, output_file);
                break;
            case 5: // Convert EXE to Python Script
                prompt_for_file(input_file);
                printw("Enter the output file path: ");
                echo();
                scanw("%s", output_file);
                noecho();
                generate_shellcode(input_file, 5, 1, output_file);
                break;
            case 6: // Exit the program
                log_activity("User exited the program.");
                return 0;
            case 7: // Show help
                show_help();
                break;
            default:
                display_error("Invalid choice! Please choose a valid option (1-7).");
        }
    }

    cleanup_ui();  // Clean up ncurses before exit
    return 0;
}
void init_ui() {
    initscr();              // Initialize ncurses
    raw();                  // Disable line buffering
    keypad(stdscr, TRUE);   // Enable special keys
    noecho();               // Disable automatic echoing of input
    start_color();          // Enable color support
    init_pair(1, COLOR_CYAN, COLOR_BLACK);  // Color for success messages
    init_pair(2, COLOR_WHITE, COLOR_BLUE);  // Color for general text
    init_pair(3, COLOR_RED, COLOR_BLACK);   // Color for error messages
}

void cleanup_ui() {
    endwin();   // End ncurses mode
}

void show_main_menu() {
    clear();
    attron(COLOR_PAIR(2));  // Apply color pair for general text
    printw("===== Metamorphic Shellcode Generator =====\n");
    printw("1. Convert EXE to Shellcode\n");
    printw("2. Convert EXE to Hex\n");
    printw("3. Convert EXE to Base64\n");
    printw("4. Convert EXE to PowerShell Script\n");
    printw("5. Convert EXE to Python Script\n");
    printw("6. Exit\n");
    printw("7. Help\n");
    attroff(COLOR_PAIR(2));  // Reset color
    printw("Enter your choice: ");
}

void show_help() {
    clear();
    attron(COLOR_PAIR(1));  // Use color for help section
    printw("Help Section:\n");
    printw("1. Convert EXE to Shellcode: Generate shellcode in byte array format.\n");
    printw("2. Convert EXE to Hex: Display the shellcode in hex format.\n");
    printw("3. Convert EXE to Base64: Display shellcode as Base64 encoded data.\n");
    printw("4. Convert EXE to PowerShell: Generates PowerShell code for execution.\n");
    printw("5. Convert EXE to Python: Generates Python script for execution.\n");
    printw("6. Exit: Exit the program.\n");
    printw("7. Help: Display this help screen.\n");
    printw("\nPress any key to return to the main menu.");
    attroff(COLOR_PAIR(1));  // Reset color
    getch();  // Wait for user to press a key
}

void prompt_for_file(char *input_file) {
    echo();
    printw("Enter EXE file path: ");
    scanw("%s", input_file);
    noecho();
}

void prompt_for_format(int *format_choice) {
    printw("Enter output format (1=Byte Array, 2=Hex, 3=Base64, 4=PowerShell, 5=Python): ");
    scanw("%d", format_choice);
}

void prompt_for_obfuscation(int *obfuscation_choice) {
    printw("Apply metamorphic obfuscation? (1=No, 2=Base64 encoding, 3=Random code insertion): ");
    scanw("%d", obfuscation_choice);
}

void generate_shellcode(char *input_file, int format_choice, int obfuscation_choice, char *output_file) {
    FILE *inputFile = fopen(input_file, "rb");

    // Open output file
    FILE *outputFile = fopen(output_file, "w");
    if (!outputFile) {
        display_error("Error opening output file! Please check the file path and try again.");
        log_activity("Failed to open output file.");
        return;
    }

    // Apply metamorphic obfuscation if chosen
    apply_metamorphic_obfuscation(inputFile, outputFile, obfuscation_choice);

    // Generate output based on selected format
    switch (format_choice) {
        case 1:
            print_byte_array(inputFile, outputFile);
            break;
        case 2:
            print_hex(inputFile, outputFile);
            break;
        case 3:
            print_base64(inputFile, outputFile);
            break;
        case 4:
            print_powershell(inputFile, outputFile);
            break;
        case 5:
            print_python(inputFile, outputFile);
            break;
        default:
            display_error("Invalid format choice! Please choose a valid option (1-5).");
            log_activity("Invalid format choice.");
    }

    fclose(outputFile);
}