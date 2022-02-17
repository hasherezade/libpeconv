#include <windows.h>
#include <stdio.h>

int popup_message1()
{
    SYSTEMTIME SystemTime;
    GetSystemTime(&SystemTime);

    char pszDate[200];
    GetDateFormatA( LOCALE_USER_DEFAULT, DATE_LONGDATE, &SystemTime, NULL, pszDate, 200 );

    return MessageBoxA(NULL, pszDate, "Test Case 1", MB_OK);
}

int popup_message2()
{
    return MessageBoxW(NULL, L"Checking wide strings", L"Test Case 1", MB_OK);
}

int main()
{
    if (popup_message1() == 1337) {
        if (popup_message2() == 1338) {
            return MessageBox(NULL, TEXT("Hooking test passed"), TEXT("Test Case 1"), MB_OK);
        }
    }
    printf("Test Case 1 finished\n");
    return 0;
}
