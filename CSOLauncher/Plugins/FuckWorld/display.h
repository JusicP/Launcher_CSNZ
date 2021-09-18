#ifndef DISPLAY_h
#define DISPLAY_h

#define RGB_YELLOWISH 0x00FFA000 // 255,160,0
#define RGB_REDISH 0x00FF1010 // 255,160,0
#define RGB_GREENISH 0x0000A000 // 0,160,0
#define RGB_LIGHTBLUE 0x006EAEC9 //134,168,195

#define HIDEMONEY_NONE	0
#define HIDEMONEY_NODRAW	1
#define HIDEMONET_EXTRAAMMO	2


#define MAX_SPRITE_NAME_LENGTH 24

#define DHN_DRAWZERO 1
#define DHN_2DIGITS 2
#define DHN_3DIGITS 4
#define DHN_4DIGITS 8
#define DHN_5DIGITS 16

#define MIN_ALPHA 100
#define FADE_TIME 100

extern int g_iC4Timer;
extern int g_iCountBg;
extern float g_fCountDown;
extern char g_sCountDownText[256];
extern int g_MoneyPosIco;
extern int g_HideMoney;

extern int g_iRes;
extern int g_iFontWidth, g_iFontHeight;

extern int g_iHealthIcon, g_iArmorIcon[2], g_iArmorFullIcon[2];

extern int g_Tga_Hero;
extern int g_iWpn_X,g_iWpn_Y;

extern client_sprite_t *g_pSpriteList;
extern int g_iSpriteCount, g_iSpriteCountAllRes;

extern HSPRITE *g_rghSprites;
extern wrect_t *g_rgrcRects;
extern char *g_rgszSpriteNames;

extern float g_flTime, g_fOldTime, g_flTimeDelta;
extern int g_iNumberZero;
extern int g_iHealth, g_iHealthFlags;
extern float g_flHealthFade;

extern int g_iArmor, g_iArmorFlags, g_iArmorType;
extern float g_flArmorFade;

extern float g_flWeaponFade;

inline HSPRITE GetSprite(int index) { return (index < 0) ? 0 : g_rghSprites[index]; }
inline wrect_t& GetSpriteRect(int index) { wrect_t x = g_rgrcRects[index]; return g_rgrcRects[index]; }

inline int GetSpriteIndex(const char *SpriteName)
{
	for (int i = 0; i < g_iSpriteCount; i++)
		if (strncmp(SpriteName, g_rgszSpriteNames + (i * MAX_SPRITE_NAME_LENGTH), MAX_SPRITE_NAME_LENGTH) == 0)
			return i;

	return -1;
}

void DisplayInitialize(void);
void DisplayRedraw(float flTime, int iIntermission);
void EngFunc_SPR_DrawAdditive(int frame, int x, int y, const wrect_t *prc);
void EngFunc_FillRGBA(int x, int y, int width, int height, int r, int g, int b, int a);
client_sprite_t *EngFunc_SPR_GetList(char *psz, int *piCount);
int DrawCrosshair(float flTime, int weaponid);

class CHudAmmo
{
public:
	void CalculateCrosshairColor(void);
	void CalculateCrosshairDrawMode(void);
	void CalculateCrosshairSize(void);
	void SetNvgOn(bool bNvg);

	int GetWeaponAccuracyFlags(int iWeaponID);

	//void Init(void);
	void VidInit(void);
	void Draw(float flTime);
	int DrawCrosshair(float flTime, int weaponid);
	int DrawCrosshairEx(float flTime, int weaponid, int iBarSize, float flCrosshairDistance, bool bAdditive, int r, int g, int b, int a);
	
private:
	float m_fFade;
	bool m_bNvgOn;
	int m_HUD_bucket0;
	int m_HUD_selection;
	HSPRITE m_hObserverCrosshair;
	wrect_t m_rcObserverCrosshair;
	int m_bObserverCrosshair;
	int m_iAmmoLastCheck;
	float m_flCrosshairDistance;
	int m_iAlpha;
	int m_R;
	int m_G;
	int m_B;
	int m_cvarR;
	int m_cvarG;
	int m_cvarB;
	int m_iCurrentCrosshair;
	bool m_bAdditive;
	int m_iCrosshairScaleBase;
	char m_szLastCrosshairColor[32];
	float m_flLastCalcTime;
};


extern CHudAmmo g_CHudAmmo;




#endif