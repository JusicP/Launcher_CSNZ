#ifndef _BIK
#define _BIK

extern int Bink_iX,Bink_iY,Bink_iCenter;

void PlayBinkInstant(char *pszName,int iStop,int iLoop);
void BinkRedraw2(void);
void BinkSetPos(int X,int Y,int Center);
void BinkSetColor(int R,int G,int B);
#endif