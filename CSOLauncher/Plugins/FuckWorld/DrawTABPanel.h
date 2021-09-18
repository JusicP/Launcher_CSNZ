#ifndef _TABPANEL
#define _TABPANEL

#define TAB_TEAM_T	1
#define TAB_TEAM_CT	2
#define TAB_SPEC	3
#define MAX_PLAYERS	32
struct team_info_t 
{
	short frags;
	short deaths;
	short ping;
	short packetloss;
	short players;
	int teamnumber;
};

extern int g_iPanelIndex,g_iPanelCanDraw;
extern team_info_t g_TeamInfo[MAX_PLAYERS];
extern hud_player_info_t	 g_PlayerInfoList[MAX_PLAYERS+1];
extern int iValidPlayer[33];
void TAB_Panel_Redraw(void);
void TAB_Panel_SortPlayers( int iTeam, char *team );
void TAB_Panel_SortTeams(void);
void TAB_Panel_GetAllPlayersInfo( void );
void TAB_Panel_Init(void);
void DrawNormalPanel(void);
void DrawZBPanel(void);
void DrawHDPanel(void);
void DrawZB4Panel(void);
void DrawZBSPanel(void);
cl_entity_t *GetPlayerByIndex(int index);

#endif