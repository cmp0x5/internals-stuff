#include <stdio.h>
#include <windows.h>

int main(void)
{
    STARTUPINFOW sui = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, BELOW_NORMAL_PRIORITY_CLASS, NULL, NULL, &sui, &pi))
    {
        printf("(-) failed to create process with error %ld\n", GetLastError());
        return EXIT_FAILURE;
    }

    DWORD PID = pi.dwProcessId;
    HANDLE hProcess = pi.hProcess;

    DWORD TID = pi.dwThreadId;
    HANDLE hThread = pi.hThread;

    /* handles in hex */
    printf("(+) process started!\npid: %ld, process handle: 0x%x\ntid: %ld, thread handle: 0x%x\n", PID, hProcess, TID, hThread);
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    printf("(+) finished! exiting...\n");
    
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;
}