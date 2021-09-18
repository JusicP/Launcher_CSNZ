#ifndef EA_H
#define EA_H

extern int g_ExtraAmmo_Draw;
extern int g_ExtraAmmo_Svdex_Num;
extern int g_ExtraAmmoIndex_Svdex,g_ExtraAmmoIndex_Musket,g_ExtraAmmoIndex_SfSniper,g_ExtraAmmoIndex_Cannon,g_ExtraAmmoIndex_M200,g_ExtraAmmoIndex_tknife,g_ExtraAmmoIndex_bow;
extern float g_fExtraAmmmoNextCanDraw;

void DrawExtraAmmoInitialize();
void DrawExtraAmmoRedraw();

int DrawExtraAmmoNumber(int x, int y,int iNumber, int r, int g, int b);

#endif