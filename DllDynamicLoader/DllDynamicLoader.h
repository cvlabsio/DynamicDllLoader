#include <windows.h>
#include <stdio.h>
#include "structs.h"

#define ARRAYSIZE 32
typedef void** HMEMMODULE;

//--------------------------------------------------------------------------------------------------------------//
// a struct that will hold some variables we might use 
struct PAYLOAD {
    PVOID pDllBytes;
    DWORD BytesNumber;
    HMEMMODULE Module;
}_PAYLOAD, * PPAYLOAD;

struct PAYLOAD DllPayload = { 0 };

//we can hold up to 32 sections, idk if there is more than that, but in that case we can update the size to more ...
PVOID lpBaseArray[ARRAYSIZE] = { 0 }; //save addresses that we wrote to, so that we can free
SIZE_T TSizeArray[ARRAYSIZE] = { 0 }; //save sizes of the memory pages we allocated
int index = 0; //how many elements we have in a array, this will be used to 'how many times we will loop when freeing'

//--------------------------------------------------------------------------------------------------------------//
// the following 2 functions, are made to add elements in the arrays we have
void AppendTSizeArray(SIZE_T Value) {
    for (int i = 0; i < ARRAYSIZE + 1; i++){
        if (TSizeArray[i] == NULL){
            TSizeArray[i] = Value;
            index++;
            break;
        }
    }
}
void AppendlpBaseArray(PVOID Value) {
    for (int i = 0; i < ARRAYSIZE + 1; i++) {
        if (lpBaseArray[i] == NULL) {
            lpBaseArray[i] = Value;
            break;
        }
    }
}

//--------------------------------------------------------------------------------------------------------------//
/// Loads the memory module.
/// <param name="lpPeModuleBuffer">The buffer containing the raw data of the module.</param>
/// <param name="bCallEntry">Call the module entry if true.</param>
/// <param name="pdwError">The error code.</param>
/// <returns>The handle to the memory module instance or NULL.</returns>
HMEMMODULE LoadMemModule(_In_ LPVOID lpPeModuleBuffer, _In_ BOOL bCallEntry, _Inout_ DWORD* pdwError);

//--------------------------------------------------------------------------------------------------------------//
BOOL LoadMemModuleInternal(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer, BOOL bCallEntry) {
    if (NULL == pMemModule  || NULL == lpPeModuleBuffer)
        return FALSE;
    pMemModule->dwErrorCode = ERROR_SUCCESS;
    // Verify file format
    if (FALSE == IsValidPEFormat(pMemModule, lpPeModuleBuffer)) {
        return FALSE;
    }
    // Map PE header and section table into memory
    if (FALSE == MapMemModuleSections(pMemModule, lpPeModuleBuffer))
        return FALSE;
    // Relocate the module base
    if (FALSE == RelocateModuleBase(pMemModule)) {
        UnmapMemModule(pMemModule);
        return FALSE;
    }
    // Resolve the import table
    if (FALSE == ResolveImportTable(pMemModule)) {
        UnmapMemModule(pMemModule);
        return FALSE;
    }
    pMemModule->dwCrc = GetCRC32(0, pMemModule->lpBase, pMemModule->dwSizeOfImage);
    // Correct the protect flag for all section pages
    if (FALSE == SetMemProtectStatus(pMemModule)) {
        UnmapMemModule(pMemModule);
        return FALSE;
    }
    // process tls data
    if (FALSE == HandleTlsData(pMemModule))
        return FALSE;
    if (bCallEntry) {
        if (FALSE == CallModuleEntry(pMemModule, DLL_PROCESS_ATTACH)) {
            // failed to call entry point,
            // clean resource, return false
            UnmapMemModule(pMemModule);
            return FALSE;
        }
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------------------------------//
HMEMMODULE LoadMemModule(_In_ LPVOID lpPeModuleBuffer, _In_ BOOL bCallEntry, _Inout_ DWORD* pdwError) {
    PMEM_MODULE pMemModule = GlobalAlloc(GPTR, sizeof(MEM_MODULE));
    if (!pMemModule) {
        if (pdwError)
            *pdwError = MMEC_INVALID_WIN32_ENV;
        return NULL;
    }
    pMemModule->bCallEntry = bCallEntry;
    pMemModule->bLoadOk = FALSE;
    pMemModule->dwErrorCode = MMEC_OK;

    if (LoadMemModuleInternal(pMemModule, lpPeModuleBuffer, bCallEntry)) {
        if (pdwError)
            *pdwError = 0;
        return (HMEMMODULE)pMemModule;
    }

    if (pdwError)
        *pdwError = pMemModule->dwErrorCode;
    GlobalFree(pMemModule);
    return NULL;
}

//--------------------------------------------------------------------------------------------------------------//
// Tests the return value and jump to exit label if false.
#define IfFalseGoExitWithError(x, exp)                                                                                 \
  do {                                                                                                                 \
    if (!(br = (x)) && (exp))                                                                                          \
      goto _Exit;                                                                                                      \
  } while (0)

//--------------------------------------------------------------------------------------------------------------//
// Tests the return value and jump to exit label if false.
#define IfFalseGoExit(x)                                                                                               \
  do {                                                                                                                 \
    if (!(br = (x)))                                                                                                   \
      goto _Exit;                                                                                                      \
  } while (0)

//--------------------------------------------------------------------------------------------------------------//
// Create a pointer value.
#define MakePointer(t, p, offset) ((t)((PBYTE)(p) + offset))

//--------------------------------------------------------------------------------------------------------------//
/// <returns>True if the data is valid PE format.</returns>
BOOL IsValidPEFormat(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer) {
    // Validate the parameters
    if (NULL == pMemModule )
        return FALSE;
    // Initialize the return value
    BOOL br = FALSE;
    // Get the DOS header
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)lpPeModuleBuffer;

    // Check the MZ signature
    IfFalseGoExit(IMAGE_DOS_SIGNATURE == pImageDosHeader->e_magic);

    // Check PE signature
    PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, lpPeModuleBuffer, pImageDosHeader->e_lfanew);
    IfFalseGoExit(IMAGE_NT_SIGNATURE == pImageNtHeader->Signature);

#ifdef _WIN64
    // Check the machine type
    if (IMAGE_FILE_MACHINE_AMD64 == pImageNtHeader->FileHeader.Machine) {
        IfFalseGoExit(IMAGE_NT_OPTIONAL_HDR64_MAGIC == pImageNtHeader->OptionalHeader.Magic);
    }
#else
    // Check the machine type
    if (IMAGE_FILE_MACHINE_I386 == pImageNtHeader->FileHeader.Machine) {
        IfFalseGoExit(IMAGE_NT_OPTIONAL_HDR32_MAGIC == pImageNtHeader->OptionalHeader.Magic);
    }
#endif
    else
        br = FALSE;

_Exit:
    // If this is invalid PE file data return error
    if (!br)
        pMemModule->dwErrorCode = MMEC_BAD_PE_FORMAT;
    return br;
}

//--------------------------------------------------------------------------------------------------------------//
// this function here is used to map all the sections
BOOL MapMemModuleSections(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer) {
    // Validate
    if (NULL == pMemModule || NULL == lpPeModuleBuffer)
        return FALSE;
    SIZE_T TSize = 0;
    // Convert to IMAGE_DOS_HEADER
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(lpPeModuleBuffer);

    // Get the pointer to IMAGE_NT_HEADERS
    PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);

    // Get the section count
    int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;

    // Get the section header
    PIMAGE_SECTION_HEADER pImageSectionHeader =
        MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

    // Find the last section limit
    DWORD dwImageSizeLimit = 0;
    for (int i = 0; i < nNumberOfSections; ++i) {
        if (0 != pImageSectionHeader[i].VirtualAddress) {
            if (dwImageSizeLimit < (pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData))
                dwImageSizeLimit = pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData;
        }
    }

    // Remove. The VirtualAlloc will do this for use
    // Align the last image size limit to the page size
    // dwImageSizeLimit = dwImageSizeLimit + pMemModule->pParams->dwPageSize - 1;
    // dwImageSizeLimit &= ~(pMemModule->pParams->dwPageSize - 1);

    // Reserve virtual memory
    LPVOID lpBase = VirtualAlloc((LPVOID)(pImageNtHeader->OptionalHeader.ImageBase), dwImageSizeLimit, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    // Failed to reserve space at ImageBase, then it's up to the system
    if (NULL == lpBase) {
        // Reserver memory in arbitrary address
        lpBase = VirtualAlloc(NULL, dwImageSizeLimit, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        // Failed again, return
        if (NULL == lpBase) {
            pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
            return FALSE;
        }
    }
    AppendlpBaseArray(lpBase);
    AppendTSizeArray(dwImageSizeLimit);
    // Commit memory for PE header
    LPVOID pDest = VirtualAlloc(lpBase, pImageNtHeader->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
    if (!pDest) {
        pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
        return FALSE;
    }
    AppendlpBaseArray(pDest);
    AppendTSizeArray(pImageNtHeader->OptionalHeader.SizeOfHeaders);
    RtlMoveMemory(pDest, lpPeModuleBuffer, pImageNtHeader->OptionalHeader.SizeOfHeaders);

    // Store the base address of this module.
    pMemModule->lpBase = pDest;
    pMemModule->dwSizeOfImage = pImageNtHeader->OptionalHeader.SizeOfImage;
    pMemModule->bLoadOk = TRUE;

    // Get the DOS header, NT header and Section header from the new PE header
    // buffer
    pImageDosHeader = (PIMAGE_DOS_HEADER)pDest;
    pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);
    pImageSectionHeader = MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

    // Map all section data into the memory
    LPVOID pSectionBase = NULL;
    LPVOID pSectionDataSource = NULL;
    for (int i = 0; i < nNumberOfSections; ++i) {
        if (0 != pImageSectionHeader[i].VirtualAddress) {
            // Get the section base
            pSectionBase = MakePointer(LPVOID, lpBase, pImageSectionHeader[i].VirtualAddress);

            if (0 == pImageSectionHeader[i].SizeOfRawData) {
                DWORD size = 0;
                if (pImageSectionHeader[i].Misc.VirtualSize > 0) {
                    size = pImageSectionHeader[i].Misc.VirtualSize;
                }
                else {
                    size = pImageNtHeader->OptionalHeader.SectionAlignment;
                }

                if (size > 0) {
                    // If the size is zero, but the section alignment is not zero then
                    // allocate memory with the alignment
                    pDest = VirtualAlloc(pSectionBase, size, MEM_COMMIT, PAGE_READWRITE);
                    if (NULL == pDest) {
                        pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
                        return FALSE;
                    }

                    // Always use position from file to support alignments smaller than
                    // page size.
                    ZeroMemory(pSectionBase, size);
                }
            }
            else {
                // Commit this section to target address
                pDest = VirtualAlloc(pSectionBase, pImageSectionHeader[i].SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
                //printf("[i] [MapMemModuleSections] 'pDest' [3]; Committing Section(s) to target address (0x%0-16p)\n", pDest);
                if (NULL == pDest) {
                    pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
                    return FALSE;
                }
                AppendlpBaseArray(pDest);
                AppendTSizeArray(pImageSectionHeader[i].SizeOfRawData);
                // Get the section data source and copy the data to the section buffer
                pSectionDataSource = MakePointer(LPVOID, lpPeModuleBuffer, pImageSectionHeader[i].PointerToRawData);
                RtlMoveMemory(pDest, pSectionDataSource, pImageSectionHeader[i].SizeOfRawData);
            }
            // Get next section header
            pImageSectionHeader[i].Misc.PhysicalAddress = (DWORD)(ULONGLONG)pDest;
        }
    }
    return TRUE;
}

//--------------------------------------------------------------------------------------------------------------//
// Relocates the module.
BOOL RelocateModuleBase(PMEM_MODULE pMemModule) {
    // Validate the parameters
    if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
        return FALSE;

    PIMAGE_NT_HEADERS pImageNtHeader =
        MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);

    // Get the delta of the real image base with the predefined
    LONGLONG lBaseDelta = ((PBYTE)pMemModule->iBase - (PBYTE)pImageNtHeader->OptionalHeader.ImageBase);

    // This module has been loaded to the ImageBase, no need to do relocation
    if (0 == lBaseDelta)
        return TRUE;

    if (0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress ||
        0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        return TRUE;

    PIMAGE_BASE_RELOCATION pImageBaseRelocation =
        MakePointer(PIMAGE_BASE_RELOCATION, pMemModule->lpBase,
            pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    if (NULL == pImageBaseRelocation) {
        pMemModule->dwErrorCode = MMEC_INVALID_RELOCATION_BASE;
        return FALSE;
    }

    while (0 != (pImageBaseRelocation->VirtualAddress + pImageBaseRelocation->SizeOfBlock)) {
        PWORD pRelocationData = MakePointer(PWORD, pImageBaseRelocation, sizeof(IMAGE_BASE_RELOCATION));

        int NumberOfRelocationData = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        for (int i = 0; i < NumberOfRelocationData; i++) {
            if (IMAGE_REL_BASED_HIGHLOW == (pRelocationData[i] >> 12)) {
                PDWORD pAddress =
                    (PDWORD)(pMemModule->iBase + pImageBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
                *pAddress += (DWORD)lBaseDelta;
            }

#ifdef _WIN64
            if (IMAGE_REL_BASED_DIR64 == (pRelocationData[i] >> 12)) {
                PULONGLONG pAddress =
                    (PULONGLONG)(pMemModule->iBase + pImageBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
                *pAddress += lBaseDelta;
            }
#endif
        }

        pImageBaseRelocation = MakePointer(PIMAGE_BASE_RELOCATION, pImageBaseRelocation, pImageBaseRelocation->SizeOfBlock);
    }

    return TRUE;
}

//--------------------------------------------------------------------------------------------------------------//
// Resolves the import table.
// this function uses pointer to loadlibrarya, getmodulehandle and getprocaddress
BOOL ResolveImportTable(PMEM_MODULE pMemModule) {
    if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
        return FALSE;


    PIMAGE_NT_HEADERS pImageNtHeader =
        MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);

    if (pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
        pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
        return TRUE;

    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor =
        MakePointer(PIMAGE_IMPORT_DESCRIPTOR, pMemModule->lpBase,
            pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; pImageImportDescriptor->Name; pImageImportDescriptor++) {
        // Get the dependent module name
        PCHAR pDllName = MakePointer(PCHAR, pMemModule->lpBase, pImageImportDescriptor->Name);

        // Get the dependent module handle
        HMODULE hMod = GetModuleHandleA(pDllName);

        // Load the dependent module
        if (NULL == hMod) {
            hMod = LoadLibraryA(pDllName);
        }
        // Failed
        if (NULL == hMod) {
            pMemModule->dwErrorCode = MMEC_IMPORT_MODULE_FAILED;
            return FALSE;
        }
        // Original thunk
        PIMAGE_THUNK_DATA pOriginalThunk = NULL;
        if (pImageImportDescriptor->OriginalFirstThunk)
            pOriginalThunk = MakePointer(PIMAGE_THUNK_DATA, pMemModule->lpBase, pImageImportDescriptor->OriginalFirstThunk);
        else
            pOriginalThunk = MakePointer(PIMAGE_THUNK_DATA, pMemModule->lpBase, pImageImportDescriptor->FirstThunk);

        // IAT thunk
        PIMAGE_THUNK_DATA pIATThunk =
            MakePointer(PIMAGE_THUNK_DATA, pMemModule->lpBase, pImageImportDescriptor->FirstThunk);

        for (; pOriginalThunk->u1.AddressOfData; pOriginalThunk++, pIATThunk++) {
            FARPROC lpFunction = NULL;
            if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {
                lpFunction = GetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal));
            }
            else {
                PIMAGE_IMPORT_BY_NAME pImageImportByName =
                    MakePointer(PIMAGE_IMPORT_BY_NAME, pMemModule->lpBase, pOriginalThunk->u1.AddressOfData);

                lpFunction = GetProcAddress(hMod, (LPCSTR) & (pImageImportByName->Name));
            }

            // Write into IAT
#ifdef _WIN64
            pIATThunk->u1.Function = (ULONGLONG)lpFunction;
#else
            pIATThunk->u1.Function = (DWORD)lpFunction;
#endif
        }
    }

    return TRUE;
}

//--------------------------------------------------------------------------------------------------------------//
// Sets the memory protected stats of all the sections.
BOOL SetMemProtectStatus(PMEM_MODULE pMemModule) {
    if (NULL == pMemModule )
        return FALSE;

    int ProtectionMatrix[2][2][2] = {
        {
            // not executable
            {PAGE_NOACCESS, PAGE_WRITECOPY},
            {PAGE_READONLY, PAGE_READWRITE},
        },
        {
            // executable
            {PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
            {PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
        },
    };


    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(pMemModule->lpBase);

    ULONGLONG ulBaseHigh = 0;
#ifdef _WIN64
    ulBaseHigh = (pMemModule->iBase & 0xffffffff00000000);
#endif

    PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);

    int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pImageSectionHeader =
        MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

    for (int idxSection = 0; idxSection < nNumberOfSections; idxSection++) {
        DWORD protectFlag = 0;
        DWORD oldProtect = 0;
        BOOL isExecutable = FALSE;
        BOOL isReadable = FALSE;
        BOOL isWritable = FALSE;

        BOOL isNotCache = FALSE;
        ULONGLONG dwSectionBase = (pImageSectionHeader[idxSection].Misc.PhysicalAddress | ulBaseHigh);
        DWORD dwSecionSize = pImageSectionHeader[idxSection].SizeOfRawData;
        if (0 == dwSecionSize)
            continue;

        // This section is in this page
        DWORD dwSectionCharacteristics = pImageSectionHeader[idxSection].Characteristics;

        // Discardable
        if (dwSectionCharacteristics & IMAGE_SCN_MEM_DISCARDABLE) {
            VirtualFree((LPVOID)dwSectionBase, dwSecionSize, MEM_DECOMMIT);
            continue;
        }

        // Executable
        if (dwSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
            isExecutable = TRUE;

        // Readable
        if (dwSectionCharacteristics & IMAGE_SCN_MEM_READ)
            isReadable = TRUE;

        // Writable
        if (dwSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
            isWritable = TRUE;

        if (dwSectionCharacteristics & IMAGE_SCN_MEM_NOT_CACHED)
            isNotCache = TRUE;

        protectFlag = ProtectionMatrix[isExecutable][isReadable][isWritable];
        if (isNotCache)
            protectFlag |= PAGE_NOCACHE;
        if (!VirtualProtect((LPVOID)dwSectionBase, dwSecionSize, protectFlag, &oldProtect)) {
            pMemModule->dwErrorCode = MMEC_PROTECT_SECTION_FAILED;
            return FALSE;
        }
    }

    return TRUE;
}

//--------------------------------------------------------------------------------------------------------------//
// Processes TLS data
// NEEDED
BOOL HandleTlsData(PMEM_MODULE pMemModule) {
    if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
        return FALSE;

    PIMAGE_NT_HEADERS pImageNtHeader =
        MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY imageDirectoryEntryTls = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (imageDirectoryEntryTls.VirtualAddress == 0)
        return TRUE;

    PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(pMemModule->iBase + imageDirectoryEntryTls.VirtualAddress);

    // TO-DO
    // here we need to process the TLS data for all running threads, this is very heavy and danger operation
    // refer to: http://www.nynaeve.net/?p=189
    // execute tls callback if any
    PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
    if (callback) {
        while (*callback) {
            (*callback)((LPVOID)pMemModule->hModule, DLL_PROCESS_ATTACH, NULL);
            callback++;
        }
    }
    return TRUE;
}

//--------------------------------------------------------------------------------------------------------------//
// Calls the module entry.
BOOL CallModuleEntry(PMEM_MODULE pMemModule, DWORD dwReason) {
    if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
        return FALSE;

    PIMAGE_NT_HEADERS pImageNtHeader =
        MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);

    Type_DllMain pfnModuleEntry = NULL;

    // If there is no entry point return false
    if (0 == pImageNtHeader->OptionalHeader.AddressOfEntryPoint) {
        return FALSE;
    }

    pfnModuleEntry = MakePointer(Type_DllMain, pMemModule->lpBase, pImageNtHeader->OptionalHeader.AddressOfEntryPoint);

    if (NULL == pfnModuleEntry) {
        pMemModule->dwErrorCode = MMEC_INVALID_ENTRY_POINT;
        return FALSE;
    }

    return pfnModuleEntry(pMemModule->hModule, dwReason, NULL);
}

//--------------------------------------------------------------------------------------------------------------//
// Unmaps all the sections.
VOID UnmapMemModule(PMEM_MODULE pMemModule) {
    if (NULL == pMemModule ||  FALSE == pMemModule->bLoadOk || NULL == pMemModule->lpBase)
        return;
    VirtualFree(pMemModule->lpBase, 0, MEM_RELEASE);
    pMemModule->lpBase = NULL;
    pMemModule->dwCrc = 0;
    pMemModule->dwSizeOfImage = 0;
    pMemModule->bLoadOk = FALSE;
}

//--------------------------------------------------------------------------------------------------------------//
// Gets the CRC32 of the data.
UINT32 GetCRC32(UINT32 uInit, void* pBuf, UINT32 nBufSize) {
#define CRC32_POLY 0x04C10DB7L
    UINT32 crc = 0;
    UINT32 Crc32table[256];
    for (int i = 0; i < 256; i++) {
        crc = (UINT32)(i << 24);
        for (int j = 0; j < 8; j++) {
            if (crc >> 31)
                crc = (crc << 1) ^ CRC32_POLY;
            else
                crc = crc << 1;
        }
        Crc32table[i] = crc;
    }

    crc = uInit;
    UINT32 nCount = nBufSize;
    PUCHAR p = (PUCHAR)pBuf;
    while (nCount--) {
        crc = (crc << 8) ^ Crc32table[(crc >> 24) ^ *p++];
    }

    return crc;
}
