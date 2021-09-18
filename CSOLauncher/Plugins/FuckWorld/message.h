#ifndef MESSAGE_H
#define MESSAGE_H

void MessageInitialize(void);
int EngFunc_HookUserMsg(char *szMsgName, pfnUserMsgHook pfn);
extern int g_iMoney;
extern int g_iBuyTime;
extern int g_Menu_Drawing;
extern int g_Menu_WaitingForMore;
extern int g_BinkScopeColor;

#endif