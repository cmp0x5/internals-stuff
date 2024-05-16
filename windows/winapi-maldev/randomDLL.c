#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD fdwReason, LPVOID lpvReserved )
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            MessageBoxW(NULL, L"hello mens))", L"messagebox loaded from dll", (MB_OK | MB_ICONQUESTION));
            break;
    
    }
    return TRUE;
}