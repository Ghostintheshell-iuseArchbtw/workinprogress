section .data
    NtCreateProcess db 'NtCreateProcess', 0
    NtOpenProcess db 'NtOpenProcess', 0
    NtTerminateProcess db 'NtTerminateProcess', 0
    NtSuspendProcess db 'NtSuspendProcess', 0
    NtResumeProcess db 'NtResumeProcess', 0
    NtCreateThread db 'NtCreateThread', 0
    NtOpenThread db 'NtOpenThread', 0
    NtTerminateThread db 'NtTerminateThread', 0
    NtSuspendThread db 'NtSuspendThread', 0
    NtResumeThread db 'NtResumeThread', 0
    NtCreateFile db 'NtCreateFile', 0
    NtOpenFile db 'NtOpenFile', 0
    NtDeleteFile db 'NtDeleteFile', 0
    NtReadFile db 'NtReadFile', 0
    NtWriteFile db 'NtWriteFile', 0
    NtCreateKey db 'NtCreateKey', 0
    NtOpenKey db 'NtOpenKey', 0
    NtDeleteKey db 'NtDeleteKey', 0
    NtSetValueKey db 'NtSetValueKey', 0
    NtGetValueKey db 'NtGetValueKey', 0
    NtCreateToken db 'NtCreateToken', 0
    NtOpenToken db 'NtOpenToken', 0
    NtDuplicateToken db 'NtDuplicateToken', 0
    NtSetInformationToken db 'NtSetInformationToken', 0
    NtQueryInformationToken db 'NtQueryInformationToken', 0

section .text
    global _start

_start:
    ; Process Management
    mov eax, 0x1a
    mov ecx, NtCreateProcess
    int 0x2e

    mov eax, 0x1b
    mov ecx, NtOpenProcess
    int 0x2e

    mov eax, 0x1c
    mov ecx, NtTerminateProcess
    int 0x2e

    mov eax, 0x1d
    mov ecx,    mov eax, 0x1d
    mov ecx, NtSuspendProcess
    int 0x2e

    mov eax, 0x1e
    mov ecx, NtResumeProcess
    int 0x2e

    ; Thread Management
    mov eax, 0x20
    mov ecx, NtCreateThread
    int 0x2e

    mov eax, 0x21
    mov ecx, NtOpenThread
    int 0x2e

    mov eax, 0x22
    mov ecx, NtTerminateThread
    int 0x2e

    mov eax, 0x23
    mov ecx, NtSuspendThread
    int 0x2e

    mov eax, 0x24
    mov ecx, NtResumeThread
    int 0x2e

    ; File Management
    mov eax, 0x30
    mov ecx, NtCreateFile
    int 0x2e

    mov eax, 0x31
    mov ecx, NtOpenFile
    int 0x2e

    mov eax, 0x32
    mov ecx, NtDeleteFile
    int 0x2e

    mov eax, 0x33
    mov ecx, NtReadFile
    int 0x2e

    mov eax, 0x34
    mov ecx, NtWriteFile
    int 0x2e

    ; Registry Management
    mov eax, 0x40
    mov ecx, NtCreateKey
    int 0x2e

    mov eax, 0x41
    mov ecx, NtOpenKey
    int 0x2e

    mov eax, 0x42
    mov ecx, NtDeleteKey
    int 0x2e

    mov eax, 0x43
    mov ecx, NtSetValueKey
    int 0x2e

    mov eax, 0x44
    mov ecx, NtGetValueKey
    int 0x2e

    ; Security Management
    mov eax, 0x50
    mov ecx, NtCreateToken
    int 0x2e

    mov eax, 0x51
    mov ecx, NtOpenToken
    int 0x2e

    mov eax, 0x52
    mov ecx, NtDuplicateToken
    int 0x2e

    mov eax, 0x53
    mov ecx, NtSetInformationToken
    int 0x2e

    mov eax, 0x54
    mov ecx, NtQueryInformationToken
    int 0x2e

    ; Exit
    mov eax, 0x60
    mov ecx, NtTerminateProcess
    int 0x2e
