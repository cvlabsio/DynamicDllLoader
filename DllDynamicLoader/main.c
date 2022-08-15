/*
	ORCA: Loads A Dll from Disk And Run its Entry Point
*/
#include <Windows.h>
#include <stdio.h>
#include "DllDynamicLoader.h"

typedef void** HMEMMODULE;

/*
	THIS FUNCTION READS THE INPUT FILE, SAVE THE SIZE OF IT AND THE PIONTER TO THE DATA READ TO A STRUCT
*/
BOOL ReadDllFile(char * FileInput) {
	HANDLE hFile;
	DWORD FileSize, lpNumberOfBytesRead;
	BOOL Succ;
	PVOID DllBytes;

	hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
	if (hFile == ERROR_FILE_NOT_FOUND) {
		printf("[!] Dll File Doesnt Exist \n");
		system("PAUSE");
		return FALSE;
	}
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] ERROR READING FILE [%d]\n", GetLastError());
		system("PAUSE");
		return FALSE;
	}
	
	FileSize = GetFileSize(hFile, NULL);
	DllBytes = malloc((SIZE_T)FileSize);

	Succ = ReadFile(hFile, DllBytes, FileSize, &lpNumberOfBytesRead, NULL);
	printf("[i] lpNumberOfBytesRead Read ::: %d \n", lpNumberOfBytesRead);
	printf("[+] DllBytes :: 0x%0-16p \n", (void*)DllBytes);
	if (!Succ) {
		printf("[!] ERROR ReadFile [%d]\n", GetLastError());
		system("PAUSE");
		return FALSE;
	}

	DllPayload.BytesNumber = lpNumberOfBytesRead;
	DllPayload.pDllBytes = DllBytes;

	CloseHandle(hFile);
	
	return TRUE;
}

/*
	RUN THE DLL'S ENTRY POINT
*/
DWORD Run(PVOID pDllBytes) {
	DWORD Error;
	HMEMMODULE hMemModule = NULL;
	hMemModule = LoadMemModule(pDllBytes, TRUE, &Error);
	//printf("[i] LoadMemModule Return Error: %d \n", Error);
	DllPayload.Module = hMemModule;
	return Error;
}

/*
	LOOPS THROUGH THE ARRAY OF POINTERS AND FREE EACH ONE BASED ON THE 2nd ARRAY (ARRAY OF SIZES)
*/
void FreeRawModule(PVOID pDllBytes) {
	printf("\n");
	for (int i = 0; i < index ; i++){
		//printf("\t[+] Freeing memory at : 0x%0-16p; of size : %ld \n", lpBaseArray[i], TSizeArray[i]);
		if (!VirtualFree(lpBaseArray[i], TSizeArray[i], MEM_DECOMMIT)) {
			printf("\t[i] VirtualFree error: %d at index : %d \n", GetLastError(), i);
		}
	}
	if (DllPayload.BytesNumber){
		ZeroMemory(pDllBytes, DllPayload.BytesNumber);
	}
}


int main(int argc, char * argv[]) {
	BOOL Succ;
	PVOID pDllBytes;
	HMEMMODULE hMemModule = NULL;
	DWORD Error;
	if (argc != 2) {
		printf("[!] Wrong Input Parameters \n");
		printf("[i] USAGE: %s <raw payload file> \n", argv[0]);
		system("PAUSE");
		system("cls");
		return -1;
	}
	Succ = ReadDllFile(argv[1]);
	if (!Succ){
		printf("[!] ReadDllFile Failed With Error: %d \n", GetLastError());
		return -1;
	}
	
	pDllBytes = DllPayload.pDllBytes;
	if (pDllBytes == NULL){
		printf("[!] pDllBytes is Null : %d \n", GetLastError());
		return -1;
	}

	printf("[i] Running . . . ");

	Error = Run(pDllBytes);
	if (Error != MMEC_OK){
		printf("[!] We Coudn't Run The Dll ... \n");
		FreeRawModule(pDllBytes);
		return -1;
	}
	printf("[+] DONE \n");
	FreeRawModule(pDllBytes);

	//printf("[i] Press Enter To exit \n");
	//getchar();
	return 0;
}