#include <Windows.h>
#include <stdio.h>

/*
    this is a dummy dll, it will pop a message box if executed
*/


BOOL Go() {
    if (MessageBox(NULL, L"Hello, If You Are Seeing This, You Are Amazing !!", L"Success", MB_OK | MB_ICONASTERISK)){
        return TRUE;
    }
    return FALSE;
}


BOOL APIENTRY DllMain( HMODULE hModule, DWORD  Reason, LPVOID lpReserved ){
    switch (Reason){
    case DLL_PROCESS_ATTACH:
        Go();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

