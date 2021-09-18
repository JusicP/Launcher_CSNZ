#ifndef OVERVIEW_H
#define OVERVIEW_H

extern int g_iBombEntity;
extern int iSprBox;
void EntityESP( void );
#define FX_PI	3.141592

int overview_calcRadarPoint(const float* origin, int& screenx, int& screeny,int iCheck,int scale);
void VectorMA (const float *veca, float scale, const float *vecb, float *vecc);
extern int g_iBombEntity;
extern float g_fBombEntityTime;

class COverview
{
public:
	COverview(void);

public:
	void Draw(void);
	bool CanDraw(void);
	void CalcRefdef(struct ref_params_s *pParams);
	void EntityESP(void);
	int CalcRadarPoint(const float* origin, int& screenx, int& screeny,int iCheck,int scale);

public:
	bool m_bCanCheck, m_bCanDraw;
	model_t *m_pSprite;
	float m_flZoom;
	int m_iHeight;
	Vector2D m_vecOrigin;
	bool m_bIsRotate;
	model_t *m_pCamera, *m_rgpPlayer[2], *m_pDeath, *m_pInfection,*m_pRadio,*m_pBackPack;
	cvar_t *m_pType, *m_pZoom, *m_pRect, *m_pAlpha,*m_pToggle;
	float m_fViewAngles_SinYaw,m_fViewAngles_CosYaw;
	int m_iMaxClient;
};
extern COverview *g_pOverview;

#endif