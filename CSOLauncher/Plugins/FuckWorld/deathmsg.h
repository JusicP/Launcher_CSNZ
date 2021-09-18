#ifndef DEATHMSG_H
#define DEATHMSG_H

#define MAX_DEATHNOTICES	8
#define MAX_PLAYER_NAME_LENGTH 64
#define DEATHNOTICE_TOP		32

struct DeathNoticeItem {
	char szKiller[32];
	char szVictim[32];
	int iId;
	int iSuicide;
	int iNonPlayerKill;
	float flDisplayTime;
	int Killer;
	int Victim;
	int iHeadShot;
	int iLocal;
};

void DeathMsg_Init(void);

int DrawConsoleString( int x, int y, const char *string );
void GetConsoleStringSize( const char *string, int *width, int *height );
int ConsoleStringLen( const char *string );
int MsgFunc_DeathMsg(const char *pszName, int iSize, void *pbuf);
void DeathMsgInit(void);
int DeathMsgRedraw( float flTime );


#endif