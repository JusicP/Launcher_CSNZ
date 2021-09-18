#ifndef _FONTTEXT
#define _FONTTEXT

#define MAX_DRAWFONTTEXT 64

struct DrawFontTextItem 
{
	int iCenter;
	char szText[2048];
	color24 color;
	int x; int y;
	float flDisplayTime;
	float flStartTime;
	float fFadeTime;
	int iScale;
	int iFillBg;
	int iChanne;
};

void DrawFontTextInitialize(void);
void DrawFontTextAdd(DrawFontTextItem rgTempDrawText);
void DrawFontTextRedraw();

#endif
