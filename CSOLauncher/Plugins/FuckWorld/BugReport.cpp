#include <metahook.h>
#include "resource.h"
#include "CrashHandle.h"
#include "util.h"

bool g_bBugReportExit = false;

HINSTANCE g_hThisModule;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	g_hThisModule = hinstDLL;
	return TRUE;
}

INT_PTR CALLBACK BugReport_WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
		case WM_INITDIALOG:
		{
			HANDLE hIcon = LoadImage(g_hThisModule, MAKEINTRESOURCE(IDI_BUGREPORTICON), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);

			if (hIcon != INVALID_HANDLE_VALUE)
			{
				SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
				SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
			}

			RECT rc;
			GetWindowRect(hWnd, &rc);

			int width = rc.right - rc.left;
			int height = rc.bottom - rc.top;

			int x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
			int y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;

			MoveWindow(hWnd, x, y, width, height, TRUE);
			return (INT_PTR)TRUE;
		}

		case WM_CREATE:
		{
			return (INT_PTR)TRUE;
		}

		case WM_COMMAND:
		{
			int wmId = LOWORD(wParam);
			int wmEvent = HIWORD(wParam);
#ifdef _DEBUG
			if (wmId == IDC_BUGENTRY)
				break;
#endif
			if (wmId == IDOK || wmId == IDCANCEL || wmId == IDC_OK)
			{
				g_bSendBugReport = (SendMessage(GetDlgItem(hWnd, IDC_SENDMDMP), BM_GETCHECK, 0, 0) == BST_CHECKED);
				g_bRestartGame = (SendMessage(GetDlgItem(hWnd, IDC_RESTARTGAME), BM_GETCHECK, 0, 0) == BST_CHECKED);
				g_bDeleteThisMDMP = (SendMessage(GetDlgItem(hWnd, IDC_DELETEMDMP), BM_GETCHECK, 0, 0) != BST_CHECKED);

				GetWindowText(GetDlgItem(hWnd, IDC_BUGENTRY), g_szBugReportDesc, sizeof(g_szBugReportDesc));
				EndDialog(hWnd, wmId);

				g_bBugReportExit = true;
				return (INT_PTR)TRUE;
			}

			break;
		}

		default: break;
	}

	return (INT_PTR)FALSE;
}

BOOL BugReport_CreateWindow(void)
{
	if (strcmp(g_szLanguage, "schinese"))
		SetThreadLocale(MAKELCID(MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), SORT_DEFAULT));

	if (DialogBox(g_hThisModule, MAKEINTRESOURCE(IDD_BUGREPORT), NULL, BugReport_WndProc) == IDOK)
		return TRUE;

#ifdef _DEBUG
	DWORD dwError = GetLastError();

	if (dwError)
	{
		char *pszError;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&pszError, 0, NULL);

		char szBuf[1024];
		sprintf(szBuf, "Failed to Create BugReport Window:\n\n%s", pszError);
		MessageBox(0, szBuf, "Debug Error", MB_OK | MB_ICONERROR);
	}
#endif
	return FALSE;
}

void BugReport_MainLoop(void)
{
	MSG msg;

	while (GetMessage(&msg, NULL, 0, 0))
	{
		if (!msg.hwnd)
			break;

		if (!TranslateAccelerator(msg.hwnd, NULL, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);

			if (g_bBugReportExit)
				break;
		}
	}
}