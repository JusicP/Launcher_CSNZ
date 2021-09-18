#ifndef _MGUI
#define _MGUI

void MGUI_Init(void);
void MGUI_Test(void);
char *Q_FindCenterString(char *p,char left,char right);
char *Q_GetCharLeft(char *p,char sym);
int MGUI_ReadFromResourceFile(char *pName);
int MGUI_ReadTypeDefClass(char *Name);
void MGUI_Init(void);

extern int g_mgui_mouseevent,g_mgui_candraw,g_mgui_file_drawing;
extern float g_mgui_nextclicktime;
#endif