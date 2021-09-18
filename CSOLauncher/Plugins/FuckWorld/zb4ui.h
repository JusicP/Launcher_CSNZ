#ifndef _zb4UI
#define _zb4UI

#define ZB4_CLASS_ZB	1
#define ZB4_CLASS_HM	2

void ZombieMod4UIInit(void);
void ZombieMod4UIRedraw(void);
void ZombieMod4UICheckTeam(int team);
void Zombie4UIParseData(int DataType, int iData);
void ZombieMod4RetinaRedraw(void); 
#endif