#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H

extern int iWidthCheck;

void Fonts_Init(char *FontName,int iW,int iH);
int Fonts_Draw(wchar_t* _strText,int x , int y, int maxW , int h);
int Fonts_Draw2(wchar_t* _strText,int x , int y, int maxW , int h, int iH);
int Fonts_GetLen(wchar_t* _strText);
int Fonts_GetHeight(wchar_t* _strText, int maxW ,int iH);
void Fonts_SetSize(int iW,int iH);
void Fonts_SetColor(int r,int g,int b,int a);
void Fonts_C2W(wchar_t *pwstr,size_t len,const char *str);
void Fonts_Free(void);
void Fonts_LoadString(wchar_t* _strText);