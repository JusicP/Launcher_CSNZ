#define PLAYTYPE_LOOP	1
#define PLAYTYPE_PLAY	2
#define PLAYTYPE_STOP	3



void PlayAudio_Init(void);
void PlayAudio_Shutdown(void);
void PlayAudio_Frame(void);
void UI_Draw();
void UI_Init(void);
extern int g_iMenuActive;
extern int g_iMouseEvent,g_iMouseOldEvent;
extern int g_iPlayStatus;
extern int g_iMini;