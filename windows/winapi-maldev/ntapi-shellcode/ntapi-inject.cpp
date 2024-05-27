#include <ntapi.h>

HMODULE GetModule(IN LPCWSTR moduleName)
{
    HMODULE hModule = NULL;
    hModule = GetModuleHandleW(moduleName);
    if (hModule == NULL)
    {
        warn("failed to get handle to module, 0x%lx\n", GetLastError());
        return NULL;
    }
    else 
    {
        okay("got handle 0x%p to module %S", hModule, moduleName);
        return hModule;
    }
}

int main(int argc, char* argv[])
{
    DWORD PID = 0;
    NTSTATUS STATUS = NULL;
    HMODULE hNTDLL = NULL;
    LPVOID baseAddress = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    
    /* const keyword makes it so sc is placed in .rdata */
    CONST UCHAR sc[] = "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41";
    SIZE_T scSize = sizeof(sc);
    
    if (argc < 2)
    {
        info("usage: %s <PID>", argv[0]);
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);
    hNTDLL = GetModule(L"NTDLL");

    /*init struct for ntOpenProcess*/
    OBJECT_ATTRIBUTES oa = {sizeof(oa), NULL };
    CLIENT_ID cid = { (HANDLE)PID, NULL };

    info("populating prototypes...");
    NtOpenProcess open = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
    NtCreateThreadEx thread = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    NtClose close = (NtClose)GetProcAddress(hNTDLL, "NtClose");
    okay("attempting injection...");

    STATUS = open(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    if (STATUS != STATUS_SUCCESS)
    {
        warn("NtOpenProcess returned NTSTATUS 0x%lx", STATUS);
        return EXIT_FAILURE;
    }
    okay("Got handle 0x%p for process %ld", hProcess, PID);


    return EXIT_SUCCESS;
}
