#ifndef WEAPONS_H
#define WEAPONS_H

#define WEAPON_P228          1
#define WEAPON_SCOUT         3
#define WEAPON_HEGRENADE     4
#define WEAPON_XM1014        5
#define WEAPON_C4            6
#define WEAPON_MAC10         7
#define WEAPON_AUG           8
#define WEAPON_SMOKEGRENADE  9
#define WEAPON_ELITE         10
#define WEAPON_FIVESEVEN     11
#define WEAPON_UMP45         12
#define WEAPON_SG550         13
#define WEAPON_GALIL         14
#define WEAPON_FAMAS         15
#define WEAPON_USP           16
#define WEAPON_GLOCK18       17
#define WEAPON_AWP           18
#define WEAPON_MP5NAVY       19
#define WEAPON_M249          20
#define WEAPON_M3            21
#define WEAPON_M4A1          22
#define WEAPON_TMP           23
#define WEAPON_G3SG1         24
#define WEAPON_FLASHBANG     25
#define WEAPON_DEAGLE        26
#define WEAPON_SG552         27
#define WEAPON_AK47          28
#define WEAPON_KNIFE         29
#define WEAPON_P90           30

#define WEAPON_VEST          31
#define CSW_VESTHELM         32

#define MAX_WEAPON_NAME		128
#define MAX_WEAPONS			32
#define MAX_AMMO_TYPES		32

struct WEAPONDATA
{
	char szName[MAX_WEAPON_NAME];
	int iClip;
	int iAmmoType;
	wrect_t rcAmmoIcon;
	int hAmmoIcon;
	wrect_t rcAmmoIcon2;
	int hAmmoIcon2;
	wrect_t rcCrosshair;
	int hCrosshair;
	wrect_t rcAutoaim;
	int hAutoaim;
};

struct WEAPON
{
	char szName[32];
	char szShell[32];
	float fShellVecScale[3];
	char szSound[64];
	char szSound2[64];
	char szSoundSilen[64];
	char szSoundSilen2[64];
	float fSoundVolume;
	float fSoundAttenuation;
	bool bHaveShellModel;
	bool bHaveShellVecScale;
	bool bHaveAnim;
	int	iAnimStart;
	int iAnimEnd;
	int	iAnimEmpty;
	int iAnimStart2;
	int iAnimEnd2;
	int iAnimSwing[2];
	int iAnimStabHit[2];
	int iAnimStab[2];
	bool bHaveShotGunSpread;
	float fShotGunSpread[3];
	int iShotGunShots;
	int iEffect;
	bool bRandomSound;
	char szSlash[5][64];
	char szSlashHit[5][64];
	char szWall[5][64];
	char szStab[5][64];
	char szStabHit[5][64];
	char szDraw[64];
	int iSlash;
	int iSlashHit;
	int iStab;
	int iStabHit;
	int iWall;
	int iAmmoDisplay;
	int iHideCrosshair;
	int iCrosshair;
	int iSniperScope[4];
	int iSniperScopeType;
	char szSniperScope[64];
};

enum weapon_effect
{
	EFFECT_NONE,
	EFFECT_BLOCK_ORIGIN,
	EFFECT_SHAKE,
	EFFECT_SHELL_M134,
	EFFECT_M1887_XMAS,
	EFFECT_TRACER_SFSNIPER,
	EFFECT_TRACER_ETHEREAL
};

extern WEAPONDATA g_iWeaponData[MAX_WEAPONS];
extern WEAPON g_WeaponData[256];
extern char g_szWeapon[33][4][32];
extern int g_iCustomWeapon[33][4];
extern int g_iAmmoCount[MAX_AMMO_TYPES];

void WeaponInitialize(void);
client_sprite_t *LoadWeaponSprite(char *psz, int *piCount);
int LoadWeaponData(char *szName);
int FindWeaponData(char *szName);

#endif