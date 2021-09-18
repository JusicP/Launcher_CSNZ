#ifndef UTIL_H
#define UTIL_H

const char *FileExtension( const char *in );
int FileExist(const char *szFile);
int LogToFile(char *szLogText, ...);
void *InterceptDLLCall(HMODULE hModule, char *szDllName, char *szFunctionName, DWORD pNewFunction);
DWORD FindPattern(char *szPattern, int iLen, DWORD dwStart, DWORD dwLen);
client_sprite_t *GetSpriteList(client_sprite_t *pList, const char *psz, int iRes, int iCount);
void UnpackRGB(int &r, int &g, int &b, unsigned long ulRGB);
void ScaleColors(int &r, int &g, int &b, int a);
#define DotProduct(x,y) ((x)[0]*(y)[0]+(x)[1]*(y)[1]+(x)[2]*(y)[2])
#define VectorSubtract(a,b,c) {(c)[0]=(a)[0]-(b)[0];(c)[1]=(a)[1]-(b)[1];(c)[2]=(a)[2]-(b)[2];}
#define VectorAdd(a,b,c) {(c)[0]=(a)[0]+(b)[0];(c)[1]=(a)[1]+(b)[1];(c)[2]=(a)[2]+(b)[2];}
#define VectorCopy(a,b) {(b)[0]=(a)[0];(b)[1]=(a)[1];(b)[2]=(a)[2];}
inline void VectorClear(float *a) { a[0]=0.0;a[1]=0.0;a[2]=0.0;}

wchar_t *UTF8ToUnicode( const char* str );
wchar_t *ANSIToUnicode( const char* str );
char *UnicodeToANSI( const wchar_t* str );
char *UnicodeToUTF8( const wchar_t* str );
wchar_t *GetLangUni(char *pLeft);
char *GetLangUtf(char *pLeft);
void MetaHookLoadLang(void);

extern char g_szLanguage[64];


#endif
