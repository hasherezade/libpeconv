#include <windows.h>
#include <stdio.h>

int popup_message1()
{
    SYSTEMTIME SystemTime;
    GetSystemTime(&SystemTime);

    TCHAR pszDate[200];
    GetDateFormat( LOCALE_USER_DEFAULT, DATE_LONGDATE, &SystemTime, NULL, pszDate, 200 );

    return MessageBox(NULL, pszDate, TEXT("Test Case 1"), MB_OK);
}

int popup_message2()
{
    return MessageBox(NULL, TEXT("Checking wide strings"), TEXT("Test Case 1"), MB_OK);
}

int main()
{
    if (popup_message1() == 1337) {
        if (popup_message2() == 1338) {
            return MessageBox(NULL, TEXT("Hooking test passed"), TEXT("Test Case 1"), MB_OK);
        }
    }
    printf("Test Case 4 finished\n");
    return 0;
}
