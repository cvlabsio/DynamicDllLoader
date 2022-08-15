#pragma once


#define MMEC_OK 0
#define MMEC_BAD_PE_FORMAT 1
#define MMEC_ALLOCATED_MEMORY_FAILED 2
#define MMEC_INVALID_RELOCATION_BASE 3
#define MMEC_IMPORT_MODULE_FAILED 4
#define MMEC_PROTECT_SECTION_FAILED 5
#define MMEC_INVALID_ENTRY_POINT 6
#define MMEC_INVALID_WIN32_ENV 0xff

/// Enums for MemModuleHelper.
typedef enum _MMHELPER_METHOD {
    MHM_BOOL_LOAD,       // Call LoadMemModule
    MHM_VOID_FREE,       // Call FreeMemModule
    MHM_FARPROC_GETPROC, // Call GetMemModuleProc
} MMHELPER_METHOD;

// Represents the memory module instance.
typedef struct __MEMMODULE_S {
    union {
#if _WIN64
        ULONGLONG iBase;
#else
        DWORD iBase;
#endif
        HMODULE hModule;
        LPVOID lpBase;
        PIMAGE_DOS_HEADER pImageDosHeader;
    };                   // MemModule base
    DWORD dwSizeOfImage; // MemModule size
    DWORD dwCrc;         // MemModule crc32

    //PAPIPTR_TABLE pApis; // Pointer to parameters
    BOOL bCallEntry;     // Call module entry
    BOOL bLoadOk;        // MemModule is loaded ok?
    DWORD dwErrorCode;   // Last error code
} MEM_MODULE, * PMEM_MODULE;

//--------------------------------------------------------------------------------------------------------------//


typedef BOOL(WINAPI* Type_DllMain)(HMODULE, DWORD, LPVOID);

BOOL LoadMemModuleInternal(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer, BOOL bCallEntry);
BOOL IsValidPEFormat(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer);
BOOL MapMemModuleSections(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer);
BOOL RelocateModuleBase(PMEM_MODULE pMemModule);
BOOL ResolveImportTable(PMEM_MODULE pMemModule);
BOOL SetMemProtectStatus(PMEM_MODULE pMemModule);
BOOL HandleTlsData(PMEM_MODULE pMemModule);
BOOL CallModuleEntry(PMEM_MODULE pMemModule, DWORD dwReason);
VOID UnmapMemModule(PMEM_MODULE pMemModule);
UINT32 GetCRC32(UINT32 uInit, void* pBuf, UINT32 nBufSize);

//--------------------------------------------------------------------------------------------------------------//


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

#ifdef _WIN64
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    BYTE Reserved3[520];
    PVOID PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
} PEB, * PPEB;
#else
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    LPVOID ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    LPVOID PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB, * PPEB;
#endif

//--------------------------------------------------------------------------------------------------------------//