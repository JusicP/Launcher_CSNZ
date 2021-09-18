#ifndef _EVENT
#define _EVENT

void Event_Init(void);

typedef enum
{
	BULLET_NONE = 0,
	BULLET_PLAYER_9MM,
	BULLET_PLAYER_MP5,
	BULLET_PLAYER_357,
	BULLET_PLAYER_BUCKSHOT,
	BULLET_PLAYER_CROWBAR,

	BULLET_MONSTER_9MM,
	BULLET_MONSTER_MP5,
	BULLET_MONSTER_12MM,

	BULLET_PLAYER_45ACP,
	BULLET_PLAYER_338MAG,
	BULLET_PLAYER_762MM,
	BULLET_PLAYER_556MM,
	BULLET_PLAYER_50AE,
	BULLET_PLAYER_57MM,
	BULLET_PLAYER_357SIG
}
Bullet;

#define INSET_IN_EYE 2
#define OBS_IN_EYE				4
#define IS_FIRSTPERSON_SPEC (g_iUser1 == OBS_IN_EYE/* || (g_iUser1 && (gHUD.m_Spectator.m_pip->value == INSET_IN_EYE))*/)

#define	PITCH 0
#define	YAW 1
#define	ROLL 2

#define AngleVectors (*gEngfuncs.pfnAngleVectors)
#define GetViewEntity (gEngfuncs.GetViewModel)

extern int g_iShotsFired;



#endif