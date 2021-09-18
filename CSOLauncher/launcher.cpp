#include <windows.h>
#include "metahook.h"
#include <IEngine.h>
#include "ExceptHandle.h"
#include "sys.h"
#include "string.h"
#include "conio.h"
#include "io.h"
#include "time.h"
#include "stdlib.h"
#include "iostream"
#include "locale.h"

HMODULE hAppInstance;

DWORD WINAPI StartThreead(LPVOID lpThreadParameter)
{
	Init("hw.dll");

	return TRUE;
}

bool RemoveHeader(HMODULE hModule)
{
	DWORD dwStartOffset = (DWORD)hModule;

	IMAGE_DOS_HEADER *pDosHeader = (PIMAGE_DOS_HEADER)dwStartOffset;

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	IMAGE_NT_HEADERS *pNtHeader = (PIMAGE_NT_HEADERS)(dwStartOffset + pDosHeader->e_lfanew);

	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return false;

	DWORD dwOldProtection = NULL;
	if (!VirtualProtect((PVOID)hModule, pNtHeader->OptionalHeader.SizeOfHeaders, PAGE_EXECUTE_READWRITE, &dwOldProtection))
		return false;

	ZeroMemory((PVOID)hModule, pNtHeader->OptionalHeader.SizeOfHeaders);
	VirtualProtect((PVOID)hModule, pNtHeader->OptionalHeader.SizeOfHeaders, dwOldProtection, &dwOldProtection);

	return true;
}

bool bFirst = false;
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
		hAppInstance = hModule;
		if (!bFirst)
		{
			bFirst = true;
			CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)StartThreead, NULL, NULL, NULL);
			DisableThreadLibraryCalls(hModule);
		}
		break;
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
