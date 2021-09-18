#ifndef DRAWIMAGE_H
#define DRAWIMAGE_H

#define MAX_DRAWIMAGE 64

struct DrawImageItem 
{
	int iFunction;
	int iCheck; // 1 is Use Hud,2 is Use Spr File!
	int iCenter;
	int iSprIndex;
	HSPRITE hl_hSprites;
	color24 color;
	int x; int y;
	int iMode;
	float flStartDisplayTime;
	float flEndDisplayTime;
	int iChanne;
	int iLength;
};

void DrawImageInitialize(void);
void DrawImageAdd(DrawImageItem rgTempDrawImage);
void DrawImageRedraw();

#endif