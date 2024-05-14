#include <windows.h>

int main(void)
{  
    MessageBoxW(NULL, L"Message Box!", L"Hello", MB_YESNO | MB_ICONINFORMATION);

    return EXIT_SUCCESS;
}