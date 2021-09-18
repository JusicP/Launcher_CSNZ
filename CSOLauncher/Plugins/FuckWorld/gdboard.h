#ifndef GDBOARD_H
#define GDBOARD_H

extern int g_iGD_Y;
extern int g_plrRank[3];
extern int g_plrFrag[33];
void MetaHookGDBoardInit(void);
void DrawGDBoardInitialize(void);
void DrawGDBoardRedraw(void);
#endif