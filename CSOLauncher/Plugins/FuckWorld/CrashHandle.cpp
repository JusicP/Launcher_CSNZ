#define _WINSOCKAPI_
#include <metahook.h>
#include <assert.h>
#include <Dbghelp.h>
#define _WIN32_WINNT 0x500
#include <Winternl.h>
#include <stdio.h>
#include "CSmtp.h"
#include "Encode.h"
#include "XorStr.h"
#include "BugReport.h"
#include "util.h"

#define USE_HOOKMDMP

#pragma comment(lib, "DbgHelp.lib")

#ifdef _DEBUG

bool symbolsinit = false;

void InitSymbols(void)
{
	if (!symbolsinit)
	{
		DWORD dwOptions = SymGetOptions();

		SymSetOptions(dwOptions | SYMOPT_LOAD_LINES);

		BOOL blah = SymInitialize(GetCurrentProcess(), NULL, TRUE);
		assert(blah);

		symbolsinit = true;
	}
}

void KillSymbols(void)
{
	if (symbolsinit)
	{
		SymCleanup(GetCurrentProcess());
		symbolsinit = false;
	}
}

#endif

LONG WINAPI GetCrashReason(LPEXCEPTION_POINTERS ep)
{
	if (!ep)
		return EXCEPTION_CONTINUE_EXECUTION;

	if (IsBadReadPtr(ep, sizeof(EXCEPTION_POINTERS)))
		return EXCEPTION_CONTINUE_EXECUTION;

#ifdef _DEBUG
	InitSymbols();

	DWORD dwLineDisp = 0;
	IMAGEHLP_LINE64 crashline = { sizeof(IMAGEHLP_LINE64), NULL, 0, NULL, 0 };

	if (SymGetLineFromAddr64(GetCurrentProcess(), (DWORD64)ep->ExceptionRecord->ExceptionAddress, &dwLineDisp, &crashline))
	{
		char msg[2048];
		sprintf(msg, "file: %s  line: %i", crashline.FileName, (int)crashline.LineNumber);
		MessageBox(NULL, msg, "An error has occurred", MB_OK | MB_ICONSTOP);
	}
	else
		MessageBox(NULL, "Unknown error", "An error has occurred", MB_OK | MB_ICONSTOP);

	KillSymbols();
#endif
#if 0
	Gamma_Restore();
#endif
	return EXCEPTION_EXECUTE_HANDLER;
}

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef struct _OBJECT_NAME_INFORMATION
{
	UNICODE_STRING Name;
}
OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

/*typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation = 0,
	ObjectNameInformation = 1,
	ObjectTypeInformation = 2
}
OBJECT_INFORMATION_CLASS;*/

BOOL (WINAPI *g_pfnMiniDumpWriteDump)(HANDLE hProcess, DWORD ProcessId, HANDLE hFile, MINIDUMP_TYPE DumpType, CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam);
NTSTATUS (NTAPI *NtQueryObject0)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);

#if defined(_WIN32) || defined(WIN32)
#define PATHSEPARATOR(c) ((c) == '\\' || (c) == '/')
#else
#define PATHSEPARATOR(c) ((c) == '/')
#endif

void V_FileBase(const char *in, char *out, int maxlen)
{
	assert(maxlen >= 1);
	assert(in);
	assert(out);

	if (!in || !in[0])
	{
		*out = 0;
		return;
	}

	int len, start, end;

	len = strlen(in);
	end = len - 1;

	while (end && in[end] != '.' && !PATHSEPARATOR(in[end]))
		end--;

	if (in[end] != '.')
		end = len - 1;
	else
		end--;

	start = len - 1;

	while (start >= 0 && !PATHSEPARATOR(in[start]))
		start--;

	if (start < 0 || !PATHSEPARATOR(in[start]))
		start = 0;
	else
		start++;

	len = end - start + 1;

	int maxcopy = min(len + 1, maxlen);

	strncpy(out, &in[start], maxcopy);
	out[maxcopy - 1] = 0;
}

bool g_bSendBugReport = false;
bool g_bRestartGame = false;
bool g_bDeleteThisMDMP = false;
char g_szBugReportDesc[1024];

BOOL WINAPI Hook_MiniDumpWriteDump(HANDLE hProcess, DWORD ProcessId, HANDLE hFile, MINIDUMP_TYPE DumpType, CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam)
{	
	BOOL result;

	if(DumpType != MiniDumpNormal)
		return TRUE;

#if 0
	Gamma_Restore();
	ExtDLL_Release();
#endif
	if (g_pInterface->CommandLine->CheckParm("-nomdmp"))
		return FALSE;
#if 0
	if (!VideoMode_IsWindowed())
		VID_SwitchFullScreen(false);

	VID_HideWindow();
	VID_CloseWindow();
#endif
	if (BugReport_CreateWindow())
		BugReport_MainLoop();

	result = g_pfnMiniDumpWriteDump(hProcess, ProcessId, hFile, DumpType, ExceptionParam, UserStreamParam, CallbackParam);

	if (result && (g_bSendBugReport || g_bDeleteThisMDMP))
	{
		POBJECT_NAME_INFORMATION pa = NULL;
		char cInfoBuffer[0x10000];
		ULONG ulSize;
		PWSTR ObjectName;

		if (NT_SUCCESS(NtQueryObject0(hFile, (OBJECT_INFORMATION_CLASS)1, cInfoBuffer, sizeof(cInfoBuffer), &ulSize)))
		{
			pa = (POBJECT_NAME_INFORMATION)cInfoBuffer;
			ObjectName = pa->Name.Buffer;

			char filebase[MAX_PATH];
			char *filename = UnicodeToANSI(ObjectName);
			char filepath[MAX_PATH], direcotry[MAX_PATH];
			DWORD dwFileSize;
			V_FileBase(filename, filebase, sizeof(filebase));
			GetCurrentDirectory(sizeof(direcotry), direcotry);
			sprintf(filepath, "%s\\%s.mdmp", direcotry, filebase);
			dwFileSize = GetFileSize(hFile, NULL);
			CloseHandle(hFile);

			if (g_bSendBugReport)
			{
				if (dwFileSize < (1024 * 1024 * 5))
				{
					CSmtp mail;
					bool isError = false;

					try
					{
						mail.SetSMTPServer(XorStr<0x13, 12, 0x139F41BA>("\x60\x79\x61\x66\x39\x69\x68\x34\x78\x73\x70" + 0x139F41BA).s, 25); // smtp.qq.com
						mail.SetSecurityType(NO_SECURITY);
						mail.SetLogin(XorStr<0xB3, 23, 0x6AF33DDC>("\xD0\xC7\xD7\xC2\xD2\xE7\xDB\xCF\xDC\xCF\xD8\xD0\xDB\xA5\xB3\x82\xB2\xB5\xEB\xA5\xA8\xA5" + 0x6AF33DDC).s); // csbte_bugsender@qq.com
						mail.SetPassword(XorStr<0xF6, 11, 0x7680F353>("\xB3\xB3\xCA\xC9\xCF\xC3\xB9\xBE\xCD\xBB" + 0x7680F353).s); // ED2058EC3D
						mail.SetSenderName(XorStr<0xBB, 16, 0xDB9F59C9>("\xD8\xCF\xDF\xCA\xDA\x9F\xA3\xB7\xA4\xB7\xA0\xA8\xA3\xAD\xBB" + 0xDB9F59C9).s); // csbte_bugsender
						mail.SetSenderMail(XorStr<0x8E, 23, 0x30E98F1A>("\xED\xFC\xF2\xE5\xF7\xCC\xF6\xE0\xF1\xE4\xFD\xF7\xFE\xFE\xEE\xDD\xEF\xEE\x8E\xC2\xCD\xCE" + 0x30E98F1A).s); // csbte_bugsender@qq.com
						mail.SetReplyTo(XorStr<0x33, 23, 0x2E1BA643>("\x50\x47\x57\x42\x52\x67\x5B\x4F\x5C\x4F\x58\x50\x5B\x25\x33\x02\x32\x35\x6B\x25\x28\x25" + 0x2E1BA643).s); // csbte_bugsender@qq.com
						mail.SetSubject(filebase);
						mail.AddRecipient(XorStr<0x23, 23, 0x0DA12156>("\x40\x57\x47\x52\x42\x77\x4B\x5F\x4C\x5E\x48\x5E\x40\x42\x45\x72\x42\x45\x1B\x55\x58\x55" + 0x0DA12156).s); // csbte_bugreport@qq.com
						mail.SetXPriority(XPRIORITY_HIGH);
						mail.SetXMailer(XorStr<0x4A, 30, 0xA907EBF5>("\x1E\x23\x29\x6D\x0C\x2E\x24\x70\x72\x7B\x22\x66\x78\x67\x6A\x70\x7A\x0B\x2E\x32\x38\x3A\x13\x12\x0B\x0C\x0A\x04\x0A" + 0xA907EBF5).s); // The Bat! (v3.02) Professional
						
						char msg[64];
						sprintf(msg, "此错误报告生成于 BTE Final %s", __DATE__);

						mail.AddMsgLine(msg);
						mail.AddMsgLine("");
						
						mail.AddMsgLine(g_szBugReportDesc);
						mail.AddAttachment(filepath);
						mail.Send();
					}
					catch (ECSmtp e)
					{
						if (!strcmp(g_szLanguage, "schinese"))
							MessageBox(NULL, e.GetErrorText().c_str(), "错误报告", MB_ICONERROR);
						else
							MessageBox(NULL, e.GetErrorText().c_str(), "Bug Report", MB_ICONERROR);

						isError = true;
					}

					if (!isError)
					{
						if (!strcmp(g_szLanguage, "schinese"))
							MessageBox(NULL, "非常感谢您的支持，我们将尽快修复此问题！", "错误报告", MB_ICONINFORMATION | MB_OK);
						else
							MessageBox(NULL, "Thank you very much for your support, we will fix this problem as soon as possible!", "Bug Report", MB_ICONINFORMATION | MB_OK);
					}
				}
			}

			if (g_bDeleteThisMDMP)
			{
				DeleteFile(filepath);
			}
		}
	}

	if (g_bRestartGame)
	{
		HANDLE hObject = CreateMutex(NULL, FALSE, "ValveHalfLifeLauncherMutex");

		if (hObject)
		{
			ReleaseMutex(hObject);
			CloseHandle(hObject);
		}

		STARTUPINFO SI;
		PROCESS_INFORMATION PI;
		memset(&SI, 0, sizeof(SI));
		memset(&PI, 0, sizeof(PI));
		SI.cb = sizeof(STARTUPINFO);

		CreateProcess(NULL, (LPSTR)g_pInterface->CommandLine->GetCmdLine(), NULL, NULL, FALSE, CREATE_NEW_PROCESS_GROUP | NORMAL_PRIORITY_CLASS, NULL, NULL, &SI, &PI);
		TerminateProcess(GetCurrentProcess(), 1);

		gEngfuncs.pfnClientCmd("_restart");
	}

	return result;
}

void CMD_Crash(void)
{
	void (*pfnCrash)(void) = NULL;
	pfnCrash();

	*(int *)0 = 0;
}

void InitCrashHandle(void)
{
	DWORD dwMiniDumpWriteDump = (DWORD)MiniDumpWriteDump;

	if (*(BYTE *)dwMiniDumpWriteDump == 0xE9)
	{
		dwMiniDumpWriteDump += 1;
		dwMiniDumpWriteDump = dwMiniDumpWriteDump + *(DWORD *)dwMiniDumpWriteDump + 0x4;
	}

#ifdef USE_HOOKMDMP
#ifndef _DEBUG
	g_pMetaHookAPI->InlineHook((void *)dwMiniDumpWriteDump, Hook_MiniDumpWriteDump, (void *&)g_pfnMiniDumpWriteDump);
	NtQueryObject0 = (NTSTATUS (NTAPI *)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG))GetProcAddress(GetModuleHandle("ntdll"), "NtQueryObject");
#endif
#else
	SetUnhandledExceptionFilter(GetCrashReason);
#endif
	//gEngfuncs.pfnAddCommand("crash", CMD_Crash);
}