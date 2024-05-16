#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("please provide a <PID> argument");
        return EXIT_FAILURE;
    }

    DWORD PID = atoi(argv[1]);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

    if (hProcess == NULL)
    {
        printf("failed to open process\n");
        return EXIT_FAILURE;
    }
    printf("got handle [0x%p] to process\n", hProcess);
    printf("closing handle...\n");
    CloseHandle(hProcess);
    printf("Done! Press [Enter] to exit...");
    (void)getchar();
    return EXIT_SUCCESS;
}