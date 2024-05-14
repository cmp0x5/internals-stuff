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

    printf("(+) process started!\npid: %ld, process handle: %ld\ntid: %ld, thread handle: %ld\n", pi.dwProcessId, pi.hProcess, pi.dwThreadId, pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    printf("(+) finished! exiting...\n");
    CloseHandle(pi.hProcess);

    return EXIT_SUCCESS;
}