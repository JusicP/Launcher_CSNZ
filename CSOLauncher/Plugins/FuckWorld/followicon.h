#ifndef FOLLOWICON_H
#define FOLLOWICON_H

#define DRAWICON_MAX	64
#define VectorCopy(a,b) {(b)[0]=(a)[0];(b)[1]=(a)[1];(b)[2]=(a)[2];}
#define VectorSubtract(a,b,c) {(c)[0]=(a)[0]-(b)[0];(c)[1]=(a)[1]-(b)[1];(c)[2]=(a)[2]-(b)[2];}

struct DrawIconItem
{
	HSPRITE hl_hSprites;   
	int iSprIndex;      //If iCheck=1
	int x,y,z;
	int iToggle;
	int iDistance;
	int iChannel;
	int r,g,b;
	int iBox;
};

extern int g_Tga_SpBox;
extern int g_Tga_SpuBox;
extern int g_Tga_BombA,g_Tga_BombB;

extern DrawIconItem g_DrawIcon[DRAWICON_MAX+1];
void DrawFollowIcon();
void DrawIconInitialize(void);
void DrawIconAdd(DrawIconItem rgTempDrawIcon);


#endif