#include "base.h"

WEAPONDATA g_iWeaponData[MAX_WEAPONS];
WEAPON g_WeaponData[256];
int g_iAmmoCount[MAX_AMMO_TYPES];
char g_szWeapon[33][4][32];
int g_iCustomWeapon[33][4];

int iTotalWeapons = 1;

void WeaponInitialize(void)
{
	memset(g_iWeaponData, 0, sizeof(g_iWeaponData));
	memset(g_iAmmoCount, 0, sizeof(g_iAmmoCount));
	memset(g_szWeapon, 0, sizeof(g_szWeapon));

	iTotalWeapons = 1;
	/*FILE* pWeaponList;
	static char szBuff[512];
	szBuff[0] = '\0';
	char szFileName[128];
	sprintf(szFileName,"metahook\\weapons.lst",g_szLanguage);
	pWeaponList = fopen(szFileName, "rt");
	if(pWeaponList == NULL)									
	{
		return;
	}
	char szTemp[258];
	int id = 0;

	while(!feof(pWeaponList))
	{
		fgets(szBuff, sizeof(szBuff)-1, pWeaponList);
		if(szBuff[strlen(szBuff)-1] == '\n') szBuff[strlen(szBuff)-1] = '\0';

		if(szBuff[0] == ';' || !szBuff[0]) continue;

		LoadWeaponData(szBuff);
	}
	fclose(pWeaponList);*/
}

client_sprite_t *LoadWeaponSprite(char *psz, int *piCount)
{
	char szSpritePath[128];

	for (int i = 1; i < MAX_WEAPONS; i++)
	{
		if (!strlen(g_iWeaponData[i].szName))
			continue;

		sprintf(szSpritePath, "sprites/%s.txt", g_iWeaponData[i].szName);

		if (strcmp(szSpritePath, psz))
			continue;

		memset(&g_iWeaponData[i].rcAmmoIcon, 0, sizeof(wrect_t));
		memset(&g_iWeaponData[i].rcAmmoIcon2, 0, sizeof(wrect_t));
		memset(&g_iWeaponData[i].rcAutoaim, 0, sizeof(wrect_t));
		memset(&g_iWeaponData[i].rcCrosshair, 0, sizeof(wrect_t));

		client_sprite_t *pList = gEngfuncs.pfnSPR_GetList(psz, piCount);

		if (!pList)
			continue;

		client_sprite_t *p;
		int ii = *piCount;
		char sz[128];
		if ((p = GetSpriteList(pList, "ammo", g_iRes, *piCount)))
		{
			sprintf(sz, "sprites/%s.spr", p->szSprite);
			g_iWeaponData[i].hAmmoIcon = gEngfuncs.pfnSPR_Load(sz);
			g_iWeaponData[i].rcAmmoIcon = p->rc;
		}

		if ((p = GetSpriteList(pList, "ammo2", g_iRes, *piCount)))
		{			
			sprintf(sz, "sprites/%s.spr", p->szSprite);
			g_iWeaponData[i].hAmmoIcon2 = gEngfuncs.pfnSPR_Load(sz);
			g_iWeaponData[i].rcAmmoIcon2 = p->rc;
		}

		if ((p = GetSpriteList(pList, "crosshair", g_iRes, *piCount)))
		{			
			sprintf(sz, "sprites/%s.spr", p->szSprite);
			g_iWeaponData[i].hCrosshair = gEngfuncs.pfnSPR_Load(sz);
			g_iWeaponData[i].rcCrosshair = p->rc;
		}

		if ((p = GetSpriteList(pList, "autoaim", g_iRes, *piCount)))
		{			
			sprintf(sz, "sprites/%s.spr", p->szSprite);
			g_iWeaponData[i].hAutoaim = gEngfuncs.pfnSPR_Load(sz);
			g_iWeaponData[i].rcAutoaim = p->rc;
		}

		if ((p = GetSpriteList(pList, "zoom", g_iRes, *piCount)))
		{
			if(pCvar_DrawScope->value && !g_WeaponData[FindWeaponData(g_iWeaponData[i].szName + 7)].iSniperScopeType)
				p->rc.bottom = p->rc.right = 1;
		}

		return pList;
	}

	return gEngfuncs.pfnSPR_GetList(psz, piCount);
}

int LoadWeaponData(char *szName)
{
	char szValue[128];
	int iValue;
	float fValue;

	sprintf(g_WeaponData[iTotalWeapons].szName, "%s", szName);


	// --------------------------
	GetPrivateProfileStringA(szName, "ShellModel", "", szValue, sizeof(szValue), "metahook/weapons.ini");
	if(szValue[0])
	{		
		g_WeaponData[iTotalWeapons].bHaveShellModel = true;
		sprintf(g_WeaponData[iTotalWeapons].szShell, "models/%s", szValue);
		/*IEngineStudio.Mod_ForName(g_WeaponData[iTotalWeapons].szShell, true);

		int id;
		gEngfuncs.CL_LoadModel(g_WeaponData[iTotalWeapons].szShell, &id);*/
	}
	else
		g_WeaponData[iTotalWeapons].bHaveShellModel = false;
	// --------------------------

	// --------------------------
	GetPrivateProfileStringA(szName, "ShellforwardScale", "!", szValue, sizeof(szValue), "metahook/weapons.ini");
	
	if(szValue[0] != '!')
	{		
		g_WeaponData[iTotalWeapons].bHaveShellVecScale = true;

		fValue = atof(szValue);
		g_WeaponData[iTotalWeapons].fShellVecScale[0] = fValue;

		GetPrivateProfileStringA(szName, "ShellupScale", "", szValue, sizeof(szValue), "metahook/weapons.ini");
		fValue = atoi(szValue);
		g_WeaponData[iTotalWeapons].fShellVecScale[1] = fValue;

		GetPrivateProfileStringA(szName, "ShellrightScale", "", szValue, sizeof(szValue), "metahook/weapons.ini");
		fValue = atoi(szValue);
		g_WeaponData[iTotalWeapons].fShellVecScale[2] = fValue;
	}
	else
		g_WeaponData[iTotalWeapons].bHaveShellVecScale = false;
	// --------------------------

	// --------------------------
	GetPrivateProfileStringA(szName, "ShootVolume", "1.0", szValue, sizeof(szValue), "metahook/weapons.ini");
	g_WeaponData[iTotalWeapons].fSoundVolume = atof(szValue);

	GetPrivateProfileStringA(szName, "ShootAttenuation", "0.0", szValue, sizeof(szValue), "metahook/weapons.ini");
	g_WeaponData[iTotalWeapons].fSoundAttenuation = atof(szValue);
	// --------------------------


	// --------------------------
	GetPrivateProfileStringA(szName, "ShootSound", "", szValue, sizeof(szValue), "metahook/weapons.ini");
	if(szValue[0])
		sprintf(g_WeaponData[iTotalWeapons].szSound, "sound/weapons/%s", szValue);
	else
		sprintf(g_WeaponData[iTotalWeapons].szSound, "sound/weapons/%s-1.wav", szName);

	GetPrivateProfileStringA(szName, "ShootSound2", "", szValue, sizeof(szValue), "metahook/weapons.ini");
	if(szValue[0])
		sprintf(g_WeaponData[iTotalWeapons].szSound2, "sound/weapons/%s", szValue);
	else
		sprintf(g_WeaponData[iTotalWeapons].szSound2, "sound/weapons/%s-2.wav", szName);

	GetPrivateProfileStringA(szName, "ShootSoundUnSilen", "", szValue, sizeof(szValue), "metahook/weapons.ini");
	if(szValue[0])
		sprintf(g_WeaponData[iTotalWeapons].szSoundSilen, "sound/weapons/%s", szValue);
	else
		sprintf(g_WeaponData[iTotalWeapons].szSoundSilen, "sound/weapons/%s_unsil-1.wav", szName);

	GetPrivateProfileStringA(szName, "ShootSoundUnSilen2", "", szValue, sizeof(szValue), "metahook/weapons.ini");
	if(szValue[0])
		sprintf(g_WeaponData[iTotalWeapons].szSoundSilen2, "sound/weapons/%s", szValue);
	else
		sprintf(g_WeaponData[iTotalWeapons].szSoundSilen2, "sound/weapons/%s_unsil-2.wav", szName);
	// --------------------------


	// --------------------------
	GetPrivateProfileStringA(szName, "ShootAnimStart", "", szValue, sizeof(szValue), "metahook/weapons.ini");
	iValue = atoi(szValue);
	if(iValue)
	{
		g_WeaponData[iTotalWeapons].bHaveAnim = true;
		g_WeaponData[iTotalWeapons].iAnimStart = iValue;

		GetPrivateProfileStringA(szName, "ShootAnimEnd", "", szValue, sizeof(szValue), "metahook/weapons.ini");
		iValue = atoi(szValue);
		g_WeaponData[iTotalWeapons].iAnimEnd = iValue;
	}
	else
		g_WeaponData[iTotalWeapons].bHaveAnim = false;

	GetPrivateProfileStringA(szName, "ShootAnimEmpty", "", szValue, sizeof(szValue), "metahook/weapons.ini");
	iValue = atoi(szValue);
	if(iValue)
		g_WeaponData[iTotalWeapons].iAnimEmpty = iValue;

	GetPrivateProfileStringA(szName, "ShootAnimStart2", "", szValue, sizeof(szValue), "metahook/weapons.ini");
	iValue = atoi(szValue);
	if(iValue)
	{
		g_WeaponData[iTotalWeapons].iAnimStart2 = iValue;

		GetPrivateProfileStringA(szName, "ShootAnimEnd2", "", szValue, sizeof(szValue), "metahook/weapons.ini");
		iValue = atoi(szValue);
		g_WeaponData[iTotalWeapons].iAnimEnd2 = iValue;
	}
	// --------------------------



	// --------------------------
	GetPrivateProfileStringA(szName, "SwingStart", "6", szValue, sizeof(szValue), "metahook/weapons.ini");
	g_WeaponData[iTotalWeapons].iAnimSwing[0] = atoi(szValue);
	GetPrivateProfileStringA(szName, "SwingEnd", "7", szValue, sizeof(szValue), "metahook/weapons.ini");
	g_WeaponData[iTotalWeapons].iAnimSwing[1] = atoi(szValue);

	GetPrivateProfileStringA(szName, "StabStart", "5", szValue, sizeof(szValue), "metahook/weapons.ini");
	g_WeaponData[iTotalWeapons].iAnimStab[0] = atoi(szValue);
	GetPrivateProfileStringA(szName, "StabEnd", "5", szValue, sizeof(szValue), "metahook/weapons.ini");
	g_WeaponData[iTotalWeapons].iAnimStab[1] = atoi(szValue);

	GetPrivateProfileStringA(szName, "StabHitStart", "4", szValue, sizeof(szValue), "metahook/weapons.ini");
	g_WeaponData[iTotalWeapons].iAnimStabHit[0] = atoi(szValue);
	GetPrivateProfileStringA(szName, "StabHitbEnd", "4", szValue, sizeof(szValue), "metahook/weapons.ini");
	g_WeaponData[iTotalWeapons].iAnimStabHit[1] = atoi(szValue);

	//sprintf(g_WeaponData[iTotalWeapons].szSound, "sound/weapons/%s_unsil-1.wav", szName);
	GetPrivateProfileStringA(szName, "RandomSound", "true", szValue, sizeof(szValue), "metahook/weapons.ini");
	if(!strcmp(szValue, "true"))
		g_WeaponData[iTotalWeapons].bRandomSound = true;
	else
		g_WeaponData[iTotalWeapons].bRandomSound = false;

	for (int i=0;i<=4;i++)
	{
		char key[16];
		sprintf(key, "Slash%d", i + 1);
		GetPrivateProfileStringA(szName, key, "", szValue, sizeof(szValue), "metahook/weapons.ini");
		if (szValue[0]) g_WeaponData[iTotalWeapons].iSlash = i;
		sprintf(g_WeaponData[iTotalWeapons].szSlash[i], "sound/weapons/%s", szValue);

		sprintf(key, "SlashHit%d", i + 1);
		GetPrivateProfileStringA(szName, key, "", szValue, sizeof(szValue), "metahook/weapons.ini");
		if (szValue[0]) g_WeaponData[iTotalWeapons].iSlashHit = i;
		sprintf(g_WeaponData[iTotalWeapons].szSlashHit[i], "sound/weapons/%s", szValue);

		sprintf(key, "Wall%d", i + 1);
		GetPrivateProfileStringA(szName, key, "", szValue, sizeof(szValue), "metahook/weapons.ini");
		if (szValue[0]) g_WeaponData[iTotalWeapons].iWall = i;
		sprintf(g_WeaponData[iTotalWeapons].szWall[i], "sound/weapons/%s", szValue);

		sprintf(key, "Stab%d", i + 1);
		GetPrivateProfileStringA(szName, key, "", szValue, sizeof(szValue), "metahook/weapons.ini");
		if (szValue[0]) g_WeaponData[iTotalWeapons].iStab = i;
		sprintf(g_WeaponData[iTotalWeapons].szStab[i], "sound/weapons/%s", szValue);

		sprintf(key, "StabHit%d", i + 1);
		GetPrivateProfileStringA(szName, key, "", szValue, sizeof(szValue), "metahook/weapons.ini");
		if (szValue[0]) g_WeaponData[iTotalWeapons].iStabHit = i;
		sprintf(g_WeaponData[iTotalWeapons].szStabHit[i], "sound/weapons/%s", szValue);
	}
	
	GetPrivateProfileStringA(szName, "Draw", "", szValue, sizeof(szValue), "metahook/weapons.ini");
	if (szValue[0])
		sprintf(g_WeaponData[iTotalWeapons].szDraw, "sound/weapons/%s", szValue);
	// --------------------------



	// --------------------------
	char szValue2[128];

	GetPrivateProfileStringA(szName, "ShotgunSpread", "0", szValue2, sizeof(szValue2), "metahook/weapons.ini");
	if (szValue2[1])
	{
		int i = 1;
		char *p;
		p = strtok(szValue2, ",");

		g_WeaponData[iTotalWeapons].fShotGunSpread[0] = atof(p);

		while(p = strtok(NULL, ","))
		{
			g_WeaponData[iTotalWeapons].fShotGunSpread[i] = atof(p);	

			i ++;
		}
	}

	GetPrivateProfileStringA(szName, "ShotgunShots", "!", szValue, sizeof(szValue), "metahook/weapons.ini");
	if(szValue[0] != '!')
	{		
		iValue = atoi(szValue);
		g_WeaponData[iTotalWeapons].iShotGunShots = iValue;
	}
	// --------------------------

	GetPrivateProfileStringA(szName, "AmmoDisplay", "0", szValue, sizeof(szValue), "metahook/weapons.ini");
	iValue = atoi(szValue);
	g_WeaponData[iTotalWeapons].iAmmoDisplay = iValue;

	GetPrivateProfileStringA(szName, "HideCrosshair", "0", szValue, sizeof(szValue), "metahook/weapons.ini");
	iValue = atoi(szValue);
	g_WeaponData[iTotalWeapons].iHideCrosshair = iValue;

	GetPrivateProfileStringA(szName, "Crosshair", "0", szValue, sizeof(szValue), "metahook/weapons.ini");
	iValue = atoi(szValue);
	g_WeaponData[iTotalWeapons].iCrosshair = iValue;

	GetPrivateProfileStringA(szName, "SniperScopeType", "0", szValue, sizeof(szValue), "metahook/weapons.ini");
	g_WeaponData[iTotalWeapons].iSniperScopeType = atoi(szValue);

	GetPrivateProfileStringA(szName, "SniperScope", "", g_WeaponData[iTotalWeapons].szSniperScope, sizeof(g_WeaponData[iTotalWeapons].szSniperScope), "metahook/weapons.ini");

	if(g_WeaponData[iTotalWeapons].iSniperScopeType == 1)
	{
		char szSniperScope[64];
		sprintf(szSniperScope, "sprites\\%s_nw", g_WeaponData[iTotalWeapons].szSniperScope);
		g_WeaponData[iTotalWeapons].iSniperScope[0] = FindTexture(szSniperScope);
		sprintf(szSniperScope, "sprites\\%s_ne", g_WeaponData[iTotalWeapons].szSniperScope);
		g_WeaponData[iTotalWeapons].iSniperScope[1] = FindTexture(szSniperScope);
		sprintf(szSniperScope, "sprites\\%s_sw", g_WeaponData[iTotalWeapons].szSniperScope);
		g_WeaponData[iTotalWeapons].iSniperScope[2] = FindTexture(szSniperScope);
		sprintf(szSniperScope, "sprites\\%s", g_WeaponData[iTotalWeapons].szSniperScope);
		g_WeaponData[iTotalWeapons].iSniperScope[3] = FindTexture(szSniperScope);
	}


	int iEffect = 0;
	GetPrivateProfileStringA(szName, "Effect", "0", szValue, sizeof(szValue), "metahook/weapons.ini");

	if (strstr(szValue, "EFFECT_SHELL_M134"))
		iEffect |= (1 << EFFECT_SHELL_M134);

	if (strstr(szValue, "EFFECT_SHAKE"))
		iEffect |= (1 << EFFECT_SHAKE);

	if (strstr(szValue, "EFFECT_M1887_XMAS"))
		iEffect |= (1 << EFFECT_M1887_XMAS);

	if (strstr(szValue, "EFFECT_BLOCK_ORIGIN"))
		iEffect |= (1 << EFFECT_BLOCK_ORIGIN);

	g_WeaponData[iTotalWeapons].iEffect = iEffect;

	iTotalWeapons ++;

	return iTotalWeapons - 1;
}
int FindWeaponData(char *szName)
{
	for (int i = 1; i <= iTotalWeapons; i++)
	{
		if(!strcmp(szName, g_WeaponData[i].szName))
			return i;
	}
	return LoadWeaponData(szName);
}