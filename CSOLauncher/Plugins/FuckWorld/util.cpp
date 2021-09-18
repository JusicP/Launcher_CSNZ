#include "base.h"
#include "baseui.h"

char g_szLang_Left[512][256];
char g_szLang_Right[512][256];
int g_szLang_Index = 0;
char g_szLanguage[64];

void GetRegKeyValueUnderRoot(const char *pszSubKey, const char *pszElement, char *pszReturnString, int nReturnLength, const char *pszDefaultValue);

void MetaHookLoadLang(void)
{
	//LogToFile( "===准备读取语言===");
	GetRegKeyValueUnderRoot("Software\\Valve\\Steam", "Language", g_szLanguage, sizeof(g_szLanguage), "english");
	LogToFile(g_szLanguage);


	
	/*LogToFile( "===准备读取语言列表===");
	FILE* pTgaList;
	static char szBuff[512];
	szBuff[0] = '\0';
	char szFileName[128];
	sprintf(szFileName,"metahook\\language\\metahook_%s.txt",g_szLanguage);
	pTgaList = fopen(szFileName, "rt");
	if(pTgaList == NULL)									
	{
		LogToFile( "语言列表打开失败");
		return;
	}
	char szTemp[258];
	int id = 0;

	while(!feof(pTgaList))
	{
		fgets(szBuff,sizeof(szBuff)-1,pTgaList);
		if(szBuff[strlen(szBuff)-1] =='\n') szBuff[strlen(szBuff)-1] = '\0';

		if(szBuff[0]==';'||!szBuff[0]) continue;
		for(int i=0;i<strlen(szBuff);i++)
		{
			if(szBuff[i] == '=')
			{
				sprintf(g_szLang_Left[g_szLang_Index],"%s",szTemp);
				id = 0;
				memset(szTemp,0,sizeof(szTemp));
				continue;
			}
			szTemp[id] = szBuff[i];
			id ++;
		}
		sprintf(g_szLang_Right[g_szLang_Index],szTemp);
		g_szLang_Index ++;
		memset(szTemp,0,sizeof(szTemp));
		id = 0;
	}
	fclose(pTgaList);
	LogToFile("共加载%d个语言词条",g_szLang_Index);*/
}
char *GetLangUtf(char *pLeft)
{
	/*for(int i=0;i<g_szLang_Index;i++)
	{
		if(!strcmp(g_szLang_Left[i],pLeft))
		{
			return g_szLang_Right[i];
		}
	}
	return "Entry Point not found";*/
	//char a[128];
	//sprintf(a,"%s",g_pLocalize->Find(pLeft));
	if(g_pLocalize->Find(pLeft))
		return UnicodeToUTF8(g_pLocalize->Find(pLeft));
	else
		return pLeft;

}
wchar_t *GetLangUni(char *pLeft)
{
	/*for(int i=0;i<g_szLang_Index;i++)
	{
		if(!strcmp(g_szLang_Left[i],pLeft))
		{
			return UTF8ToUnicode(g_szLang_Right[i]);
		}
	}
	return L"Entry Point not found";*/
	//char a[128];
	//sprintf(a,"%s",g_pLocalize->Find(pLeft));
	if(g_pLocalize->Find(pLeft))
		return g_pLocalize->Find(pLeft);
	else
		return ANSIToUnicode(pLeft);
}
wchar_t *ANSIToUnicode( const char* str )
{
   int textlen ;
   static wchar_t result[1024];
   textlen = MultiByteToWideChar( CP_ACP, 0, str,-1, NULL,0 ); 
   memset(result, 0, sizeof(char) * ( textlen + 1 ) );
   MultiByteToWideChar(CP_ACP, 0,str,-1,(LPWSTR)result,textlen ); 
   return result; 
}
char *UnicodeToANSI( const wchar_t* str )
{
     static char result[1024];
     int textlen;
     textlen = WideCharToMultiByte( CP_ACP, 0, str, -1, NULL, 0, NULL, NULL );
     memset(result, 0, sizeof(char) * ( textlen + 1 ) );
     WideCharToMultiByte( CP_ACP, 0, str, -1, result, textlen, NULL, NULL );
     return result;
}
wchar_t *UTF8ToUnicode( const char* str )
{
     int textlen ;
     static wchar_t result[1024];
     textlen = MultiByteToWideChar( CP_UTF8, 0, str,-1, NULL,0 ); 
     memset(result, 0, sizeof(char) * ( textlen + 1 ) );
     MultiByteToWideChar(CP_UTF8, 0,str,-1,(LPWSTR)result,textlen ); 
     return result; 
}
char *UnicodeToUTF8( const wchar_t* str )
{
	static char result[1024];
	int textlen;
	textlen = WideCharToMultiByte( CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL );
	memset(result, 0, sizeof(char) * ( textlen + 1 ) );
	WideCharToMultiByte( CP_UTF8, 0, str, -1, result, textlen, NULL, NULL );
	return result;
}
const char *FileExtension( const char *in )
{
	const char *separator, *backslash, *colon, *dot;

	separator = strrchr( in, '/' );
	backslash = strrchr( in, '\\' );
	if( !separator || separator < backslash ) separator = backslash;
	colon = strrchr( in, ':' );
	if( !separator || separator < colon ) separator = colon;

	dot = strrchr( in, '.' );
	if( dot == NULL || ( separator && ( dot < separator )))
		return "";
	return dot + 1;
}

int FileExist(const char *szFile)
{
	DWORD dAttrib = GetFileAttributes(szFile);

	if (dAttrib == INVALID_FILE_ATTRIBUTES || dAttrib == FILE_ATTRIBUTE_DIRECTORY)
		return 0;

	return 1;
}

int LogToFile(char *szLogText, ...)
{
	FILE *fp;

	if (!(fp = fopen("metahook\\logs\\metahook.log", "a")))
		return 0;
	
	va_list vArgptr;
	char szText[1024];

	va_start(vArgptr, szLogText);
	vsprintf(szText, szLogText, vArgptr);
	va_end(vArgptr);

	SYSTEMTIME systime;
	::GetLocalTime(&systime);


	fprintf(fp, "[%02d:%02d:%02d.%03d] %s\n", systime.wHour,systime.wMinute,systime.wSecond,systime.wMilliseconds,szText);
	fclose(fp);
	return 1;
}

void *InterceptDLLCall(HMODULE hModule, char *szDLLName, char *szFunctionName, DWORD pNewFunction)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNTHeader;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
	PIMAGE_THUNK_DATA pThunk;
	DWORD dwOldProtect, dwOldProtect2;
	void *pOldFunction;

	#define MakePtr(cast, ptr, addValue)(cast)((DWORD)(ptr) + (DWORD)(addValue))

	if (!(pOldFunction = GetProcAddress(GetModuleHandle(szDLLName), szFunctionName)))
		return 0;

	pDosHeader = (PIMAGE_DOS_HEADER)hModule;

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	pNTHeader = MakePtr(PIMAGE_NT_HEADERS, pDosHeader, pDosHeader->e_lfanew);

	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE || (pImportDesc = MakePtr(PIMAGE_IMPORT_DESCRIPTOR, pDosHeader, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)) == (PIMAGE_IMPORT_DESCRIPTOR)pNTHeader)
		return NULL;

	while (pImportDesc->Name)
	{
		if (!stricmp(MakePtr(char *, pDosHeader, pImportDesc->Name), szDLLName))
			break;

		pImportDesc++;
	}

	if (pImportDesc->Name == NULL)
		return NULL;

	pThunk = MakePtr(PIMAGE_THUNK_DATA, pDosHeader, pImportDesc->FirstThunk);

	while (pThunk->u1.Function)
	{
		if (pThunk->u1.Function == (DWORD)pOldFunction)
		{
			VirtualProtect((void *)&pThunk->u1.Function, sizeof(PDWORD), PAGE_EXECUTE_READWRITE, &dwOldProtect);
			pThunk->u1.Function=(DWORD)pNewFunction;
			VirtualProtect((void *)&pThunk->u1.Function, sizeof(PDWORD), dwOldProtect, &dwOldProtect2);
			return pOldFunction;
		}

		pThunk++;
	}

	return NULL;
}

DWORD FindPattern(char *szPattern, int iLen, DWORD dwStart, DWORD dwLen)
{ 
	char *szStart = (char *)dwStart; 
	for(; (DWORD)szStart < (dwStart + dwLen); szStart++) 
		if(!memcmp(szStart, szPattern, iLen)) 
			return (DWORD)szStart; 

	return NULL; 
}

client_sprite_t *GetSpriteList(client_sprite_t *pList, const char *psz, int iRes, int iCount)
{
	if (!pList)
		return NULL;

	int i = iCount;
	client_sprite_t *p = pList;

	while(i--)
	{
		if ((!strcmp(psz, p->szName)) && (p->iRes == iRes))
			return p;
		p++;
	}

	return NULL;
}

void UnpackRGB(int &r, int &g, int &b, unsigned long ulRGB)
{
	r = (ulRGB & 0xFF0000) >>16;
	g = (ulRGB & 0xFF00) >> 8;
	b = ulRGB & 0xFF;
}

void ScaleColors(int &r, int &g, int &b, int a)
{
	float x = (float)a / 255;
	r = (int)(r * x);
	g = (int)(g * x);
	b = (int)(b * x);
}

void GetRegKeyValueUnderRoot(const char *pszSubKey, const char *pszElement, char *pszReturnString, int nReturnLength, const char *pszDefaultValue)
{
	LONG lResult;
	HKEY hKey;
	char szBuff[128];
	DWORD dwDisposition;
	DWORD dwType;
	DWORD dwSize;

	sprintf(pszReturnString, "%s", pszDefaultValue);
	lResult = RegCreateKeyExA(HKEY_CURRENT_USER, pszSubKey, 0, "String", REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition);

	if (lResult != ERROR_SUCCESS)
		return;

	if (dwDisposition == REG_CREATED_NEW_KEY)
	{
		RegSetValueEx(hKey, pszElement, 0, REG_SZ, (CONST BYTE *)pszDefaultValue, strlen(pszDefaultValue) + 1);
	}
	else
	{
		dwSize = nReturnLength;
		lResult = RegQueryValueEx(hKey, pszElement, 0, &dwType, (unsigned char *)szBuff, &dwSize);

		if (lResult == ERROR_SUCCESS)
		{
			if (dwType == REG_SZ)
			{
				strncpy(pszReturnString, szBuff, nReturnLength);
				pszReturnString[nReturnLength - 1] = '\0';
			}
		}
		else
			RegSetValueEx(hKey, pszElement, 0, REG_SZ, (CONST BYTE *)pszDefaultValue, strlen(pszDefaultValue) + 1);
	}

	RegCloseKey(hKey);
}
