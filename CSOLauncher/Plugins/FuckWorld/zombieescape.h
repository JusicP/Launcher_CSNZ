#ifndef _ZE_
#define _ZE_

extern int g_ze_hm,g_ze_zb,g_ze_flag,g_ze_me,g_ze_bar;
extern int g_bit_hm,g_bit_zb;
extern int g_zenum_hm[21],g_zenum_zb[21],g_player_lastcount[33];
extern float g_iZeCheck;
extern float g_ZePoint[20][3];
void ZombieEscapeRedraw(void);
void ResetZe(void);
int LoadZePoint(char *pName);

#endif




