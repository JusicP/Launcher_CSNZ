#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <direct.h>
#include <psapi.h> 
#include "CSOLauncher_Dll_Raw.h"

#define GetCurrentDir _getcwd

#define DLLPATHLEN 256

BOOL AdjustProcessPrivilege(HANDLE hProcess, LPCTSTR Privilege, BOOL bEnable) {
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	// �������� ����� ��������

	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	// �������� LUID ��� �������� ����������
	LookupPrivilegeValue(NULL, Privilege, &tkp.Privileges[0].Luid);

	tkp.PrivilegeCount = 1;  //���-�� ����������
	tkp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0; //�������� ����������

	// ��������� �������� ���������� ��� ��������
	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

	CloseHandle(hToken);

	return GetLastError() == ERROR_SUCCESS;
}

class Injector
{
private:
	DWORD dwProcessID;
	PROCESSENTRY32 pe32;
	HANDLE hProcSnapShot;
	HANDLE hProcHandle;
	HANDLE hThreadHandle;
	LPVOID DllAllocateAddress;
	FARPROC LoadLibraryAddress;
	LPTHREAD_START_ROUTINE startExecutionAddress;
	TCHAR DllAbsPath[DLLPATHLEN];

public:
	Injector(LPCTSTR DllPath, int processName) :
		dwProcessID(processName),
		pe32({ sizeof(PROCESSENTRY32) }),
		hProcSnapShot(NULL),
		hProcHandle(NULL),
		hThreadHandle(NULL),
		DllAllocateAddress(NULL),
		LoadLibraryAddress(NULL),
		startExecutionAddress(NULL)
	{
		// Getting the absolute path of the DLL file
		if (!GetFullPathName(DllPath, DLLPATHLEN, DllAbsPath, NULL))
			Debug(0x01);

		// Start looking for our target process
		hProcSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (hProcSnapShot == INVALID_HANDLE_VALUE)
			Debug(0x02);

		if (!Process32First(hProcSnapShot, &pe32))
			Debug(0x03);

		/*do
		{
			if (!strcmp(pe32.szExeFile, ProcessName))
			{
				dwProcessID = pe32.th32ProcessID;
				CloseHandle(hProcSnapShot);
				break;
			}
		} while (Process32Next(hProcSnapShot, &pe32));*/
	}

	~Injector()
	{
		CloseHandle(hProcHandle);
		VirtualFreeEx(hProcHandle, DllAllocateAddress, strlen(DllAbsPath), MEM_DECOMMIT | MEM_RELEASE);
	}

	void Debug(BYTE ErrorCode = 0x00)
	{

		switch (ErrorCode)
		{
		case 0x01:
			std::cout << "[CSOLauncher] 0x01 error. Couldn't get DLL Absolute Path! " << GetLastError() << std::endl;
			break;
		case 0x02:
			std::cout << "[CSOLauncher] 0x02 error. Couldn't open process snapshot handle! " << GetLastError() << std::endl;
			break;
		case 0x03:
			std::cout << "[CSOLauncher] 0x03 error. Couldn't retrieve information about the first process in system snapshot! " << GetLastError() << std::endl;
			break;
		case 0x04:
			std::cout << "[CSOLauncher] 0x04 error. Couldn't open process memory space! " << GetLastError() << std::endl;
			break;
		case 0x05:
			break;
		case 0x06:
			std::cout << "[CSOLauncher] 0x05 error. Couldn't write DLL into allocated memory space! " << GetLastError() << std::endl;
			break;
		case 0x07:
			std::cout << "[CSOLauncher] 0x06 error. Couldn't load LoadLibrary function! " << GetLastError() << std::endl;
			break;
		case 0x08:
			std::cout << "[CSOLauncher] 0x07 error. Couldn't create new thread! " << GetLastError() << std::endl;
			break;
		default:
			return;
		}
		system("PAUSE");
		exit(-1);
	}

	BOOL SetDebugPriviledge(BOOL State)
	{
		HANDLE hToken;
		TOKEN_PRIVILEGES tp;
		DWORD dwSize;
		ZeroMemory(&tp, sizeof(tp));
		tp.PrivilegeCount = 1;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
		{
			return FALSE;
		}
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
		{
			CloseHandle(hToken);
		}
		if (State)
		{
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		}
		else
		{
			tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
		}
		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, &dwSize))
		{
			CloseHandle(hToken);
		}
		return CloseHandle(hToken);
	}

	bool InjectDll()
	{
		// Attach to process memory space
		printf("%d\n", dwProcessID);
		//AdjustProcessPrivilege(GetCurrentProcess(), "SeDebugPrivilege", TRUE);
		SetDebugPriviledge(TRUE);
		hProcHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, dwProcessID);

		if (!hProcHandle)
			Debug(0x04);

		// Allocate memory space to inject the DLL absolute path in target process
		DllAllocateAddress = VirtualAllocEx(hProcHandle, NULL, strlen(DllAbsPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!DllAllocateAddress)
			Debug(0x05);

		// Write DLL into target allocated memory space
		if (!WriteProcessMemory(hProcHandle, DllAllocateAddress, DllAbsPath, strlen(DllAbsPath), NULL))
			Debug(0x06);

		// Load the written DLL using LoadLibrary
		LoadLibraryAddress = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");

		if (!LoadLibraryAddress)
			Debug(0x07);


		// Create and start executing new thread
		startExecutionAddress = (LPTHREAD_START_ROUTINE)LoadLibraryAddress;

		hThreadHandle = CreateRemoteThread(hProcHandle, NULL, 0, startExecutionAddress, DllAllocateAddress, 0, NULL);

		if (!hThreadHandle)
			Debug(0x08);

		Debug();

		return true;
	}

};
#define MAX_PROCESSES 1024
typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI *PDLL_MAIN)(HMODULE, DWORD, PVOID);

typedef struct _MANUAL_INJECT
{
	PVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
}MANUAL_INJECT, *PMANUAL_INJECT;
DWORD WINAPI LoadDll(PVOID p)
{
	PMANUAL_INJECT ManualInject;

	HMODULE hModule;
	DWORD i, Function, count, delta;

	PDWORD ptr;
	PWORD list;

	PIMAGE_BASE_RELOCATION pIBR;
	PIMAGE_IMPORT_DESCRIPTOR pIID;
	PIMAGE_IMPORT_BY_NAME pIBN;
	PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;

	PDLL_MAIN EntryPoint;

	ManualInject = (PMANUAL_INJECT)p;

	pIBR = ManualInject->BaseRelocation;
	delta = (DWORD)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

																										  // Relocate the image

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			list = (PWORD)(pIBR + 1);

			for (i = 0; i<count; i++)
			{
				if (list[i])
				{
					ptr = (PDWORD)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}
		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	pIID = ManualInject->ImportDirectory;

	// Resolve DLL imports

	while (pIID->Characteristics)
	{
		OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

		hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);

		if (!hModule)
		{
			return FALSE;
		}

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal

				Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			else
			{
				// Import by name

				pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
				Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			OrigFirstThunk++;
			FirstThunk++;
		}

		pIID++;
	}

	if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}

	return TRUE;
}
DWORD WINAPI LoadDllEnd()
{
	return 0;
}
DWORD ProcId = 0;

DWORD FindProcess(__in_z LPCTSTR lpcszFileName)
{
	LPDWORD lpdwProcessIds;
	LPTSTR  lpszBaseName;
	HANDLE  hProcess;
	DWORD   i, cdwProcesses, dwProcessId = 0;

	lpdwProcessIds = (LPDWORD)HeapAlloc(GetProcessHeap(), 0, MAX_PROCESSES * sizeof(DWORD));
	if (lpdwProcessIds != NULL)
	{
		if (EnumProcesses(lpdwProcessIds, MAX_PROCESSES * sizeof(DWORD), &cdwProcesses))
		{
			lpszBaseName = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, MAX_PATH * sizeof(TCHAR));
			if (lpszBaseName != NULL)
			{
				cdwProcesses /= sizeof(DWORD);
				for (i = 0; i < cdwProcesses; i++)
				{
					hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lpdwProcessIds[i]);
					if (hProcess != NULL)
					{
						if (GetModuleBaseName(hProcess, NULL, lpszBaseName, MAX_PATH) > 0)
						{
							if (!lstrcmpi(lpszBaseName, lpcszFileName))
							{
								dwProcessId = lpdwProcessIds[i];
								CloseHandle(hProcess);
								break;
							}
						}
						CloseHandle(hProcess);
					}
				}
				HeapFree(GetProcessHeap(), 0, (LPVOID)lpszBaseName);
			}
		}
		HeapFree(GetProcessHeap(), 0, (LPVOID)lpdwProcessIds);
	}
	return dwProcessId;
}
DWORD MyGetProcessId(LPCTSTR ProcessName)
{
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) {
		do {
			if (!lstrcmpi(pt.szExeFile, ProcessName)) {
				CloseHandle(hsnap);
				return pt.th32ProcessID;
			}
		} while (Process32Next(hsnap, &pt));
	}
	CloseHandle(hsnap);
	return 0;
}

PIMAGE_DOS_HEADER pIDH;
PIMAGE_NT_HEADERS pINH;
PIMAGE_SECTION_HEADER pISH;
HANDLE hProcess, hThread, hFile, hToken;
PVOID buffer, image, mem;
DWORD i, FileSize, ProcessId, ExitCode, read;
TOKEN_PRIVILEGES tp;
MANUAL_INJECT ManualInject;

bool autbypass = false;

DWORD kjclkjclk2jlkjsafd()
{
	while (true)
	{
		if (FindProcess("cstrike-online.exe"))
		{
			PVOID rData = reinterpret_cast<char*>(/*rawData*/NULL);
			pIDH = (PIMAGE_DOS_HEADER)/*Memory*/rData;
			pINH = (PIMAGE_NT_HEADERS)((LPBYTE)/*Memory*/rData + pIDH->e_lfanew);

			DWORD pid = MyGetProcessId(/*Process Name*/"cstrike-online.exe");
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

			image = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			WriteProcessMemory(hProcess, image, /*Memory*/rData, pINH->OptionalHeader.SizeOfHeaders, NULL);
			pISH = (PIMAGE_SECTION_HEADER)(pINH + 1);
			for (i = 0; i<pINH->FileHeader.NumberOfSections; i++)
			{
				WriteProcessMemory(hProcess, (PVOID)((LPBYTE)image + pISH[i].VirtualAddress),
					(PVOID)((LPBYTE)rData/*Memory*/ + pISH[i].PointerToRawData), pISH[i].SizeOfRawData, NULL);
			}
			mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			memset(&ManualInject, 0, sizeof(MANUAL_INJECT));

			ManualInject.ImageBase = image;
			ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew);
			ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			ManualInject.fnLoadLibraryA = LoadLibraryA;
			ManualInject.fnGetProcAddress = GetProcAddress;

			WriteProcessMemory(hProcess, mem, &ManualInject, sizeof(MANUAL_INJECT), NULL);
			WriteProcessMemory(hProcess, (PVOID)((PMANUAL_INJECT)mem + 1), LoadDll, (DWORD)LoadDllEnd - (DWORD)LoadDll, NULL);
			Sleep(6000);

			hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((PMANUAL_INJECT)mem + 1), mem, 0, NULL);
			WaitForSingleObject(hThread, INFINITE);
			GetExitCodeThread(hThread, &ExitCode);
			ExitProcess(0);
		}
	}
}

int main(int argc, char *argv[])
{
	char pGameExePath[1024];
	char pLauncherPath[1024];
	char cCurrentPath[FILENAME_MAX];
	GetCurrentDir(cCurrentPath, sizeof(cCurrentPath));
	cCurrentPath[sizeof(cCurrentPath) - 1] = '\0';
	sprintf(pGameExePath, "%s\\cstrike-online.exe", cCurrentPath);
	sprintf(pLauncherPath, "%s\\CSOLauncher.dll", cCurrentPath);

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	char command[1024]; // size to be adjusted
	int i;
	for (*command = 0, i = 1; i < argc; i++) {
		if (i > 1) strcat(command, " ");
		//strcat(command, "\"");
		strcat(command, argv[i]);
	//	strcat(command, "\"");
	}

	if (CreateProcess(pGameExePath,
		GetCommandLine(),
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi
	))
	{
		Injector InjectorObject(pLauncherPath, pi.dwProcessId);
		InjectorObject.InjectDll();

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	//kjclkjclk2jlkjsafd();

	return 0;
}