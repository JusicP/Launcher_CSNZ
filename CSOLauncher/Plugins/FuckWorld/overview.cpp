#include "base.h"

COverview *g_pOverview;

int g_iBombEntity = 0;
float g_fBombEntityTime = 0;
#define CALC_SCALE	1.4
#define CAMETA_BORDER	80
#define SCALE	8



COverview::COverview(void)
{
	m_pRect = gEngfuncs.pfnRegisterVariable("mh_dynamicradar_rect", "200", FCVAR_ARCHIVE);
	m_pToggle = gEngfuncs.pfnRegisterVariable("mh_dynamicradar_draw", "1", FCVAR_ARCHIVE);
}
void COverview::CalcRefdef(struct ref_params_s *pParams)
{
	VectorCopy(pParams->viewangles,mainViewAngles);
	VectorCopy(pParams->vieworg,mainViewOrigin);

	float fYaw = pParams->viewangles[1]*(FX_PI/180.0);
	m_fViewAngles_SinYaw = sin(fYaw);
	m_fViewAngles_CosYaw = cos(fYaw);

		
	displayCenterX = g_sScreenInfo.iWidth/2;
	displayCenterY = g_sScreenInfo.iHeight/2;
	return;
} 
int COverview::CalcRadarPoint(const float* origin, int& screenx, int& screeny,int iCheck,int scale)
{
	int iReturn = 0;
	float dx  = origin[0] - g_vecEyePos[0];
	float dy  = origin[1] - g_vecEyePos[1];

	float x =  dx*  m_fViewAngles_SinYaw   -  dy*m_fViewAngles_CosYaw;
	float y =  dx*(-m_fViewAngles_CosYaw)  -  dy*m_fViewAngles_SinYaw;

	screenx =m_pRect->value / 2 +x/10*m_flZoom;
	screeny =m_pRect->value / 2 +y/10*m_flZoom;

	// Check Point (For Overview Spr Icon)
	if(iCheck)
	{
		if(screenx < scale/2)
		{
			screenx = scale/CALC_SCALE;
			iReturn = 1;
		}
		if(screenx > m_pRect->value-scale/2)
		{
			screenx = m_pRect->value - scale/CALC_SCALE;
			iReturn = 1;
		}
		if(screeny < scale/2)
		{
			screeny = scale/CALC_SCALE;
			iReturn = 1;
		}
		if(screeny > m_pRect->value-scale/2)
		{
			screeny = m_pRect->value - scale/CALC_SCALE;
			iReturn = 1;
		}
	}
	return iReturn;	
}
void COverview::Draw(void)
{
	if (!m_pToggle->value) return;
	if (!m_bCanDraw) return;

	float screenaspect, xs, ys, xStep, yStep, x,y,z;
	int ix,iy,i,xTiles,yTiles,frame;

	i = m_pSprite->numframes / (4*3);
	i = sqrt(float(i));
	xTiles = i*4;
	yTiles = i*3;
	screenaspect = 4.0f/3.0f;	
	xs = m_vecOrigin.x;
	ys = m_vecOrigin.y;
	z  = mainViewOrigin[2] - (10+1.2*g_pOverview->m_pRect->value)*4.1f/g_pOverview->m_flZoom;
	gEngfuncs.pTriAPI->RenderMode( kRenderTransTexture );
	gEngfuncs.pTriAPI->CullFace( TRI_NONE );
	gEngfuncs.pTriAPI->Color4f( 1.0, 1.0, 1.0, 0.8 );

	frame = 0;
	int numframes = ModelFrameCount(m_pSprite);
	if ( m_bIsRotate )
	{
		xStep = (2*4096.0f / m_flZoom ) / xTiles;
		yStep = -(2*4096.0f / (m_flZoom* screenaspect) ) / yTiles; 
		y = ys + (4096.0f / (m_flZoom * screenaspect));
		for (iy = 0; iy < yTiles; iy++)
		{
			x = xs - (4096.0f / (m_flZoom));
			for (ix = 0; ix < xTiles; ix++)
			{
				if (frame >= numframes)
					break;
				
				Tri_TexParameteri ( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, 0x8370 );
				Tri_TexParameteri ( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, 0x8370 );
				gEngfuncs.pTriAPI->SpriteTexture( m_pSprite, frame );
				gEngfuncs.pTriAPI->Begin( TRI_QUADS );
				gEngfuncs.pTriAPI->TexCoord2f( 0, 0 );
				gEngfuncs.pTriAPI->Vertex3f (x, y, z);
				gEngfuncs.pTriAPI->TexCoord2f( 1, 0 );
				gEngfuncs.pTriAPI->Vertex3f (x+xStep ,y,  z);
				gEngfuncs.pTriAPI->TexCoord2f( 1, 1 );
				gEngfuncs.pTriAPI->Vertex3f (x+xStep, y+yStep, z);
				gEngfuncs.pTriAPI->TexCoord2f( 0, 1 );
				gEngfuncs.pTriAPI->Vertex3f (x, y+yStep, z);
				gEngfuncs.pTriAPI->End();
				frame++;
				x+= xStep;
			}
			y+=yStep;
		}
	} 
	else
	{
		xStep = -(2*4096.0f / m_flZoom ) / xTiles;
		yStep = -(2*4096.0f / (m_flZoom* screenaspect) ) / yTiles;	
		x = xs + (4096.0f / (m_flZoom * screenaspect ));
		for (ix = 0; ix < yTiles; ix++)
		{
			y = ys + (4096.0f / (m_flZoom));			
			for (iy = 0; iy < xTiles; iy++)	
			{
				if (frame >= numframes)
					break;
				
				Tri_TexParameteri ( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, 0x8370 );
				Tri_TexParameteri ( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, 0x8370 );
				gEngfuncs.pTriAPI->SpriteTexture( m_pSprite, frame );
				gEngfuncs.pTriAPI->Begin( TRI_QUADS );
				gEngfuncs.pTriAPI->TexCoord2f( 0, 0 );
				gEngfuncs.pTriAPI->Vertex3f (x, y, z);
				gEngfuncs.pTriAPI->TexCoord2f( 0, 1 );
				gEngfuncs.pTriAPI->Vertex3f (x+xStep ,y,  z);
				gEngfuncs.pTriAPI->TexCoord2f( 1, 1 );
				gEngfuncs.pTriAPI->Vertex3f (x+xStep, y+yStep, z);
				gEngfuncs.pTriAPI->TexCoord2f( 1, 0 );
				gEngfuncs.pTriAPI->Vertex3f (x, y+yStep, z);
				gEngfuncs.pTriAPI->End();
				frame++;
				y+=yStep;
			}
			x+= xStep;
		}
	}
}
bool COverview::CanDraw(void)
{
	return m_pSprite && m_pToggle->value && !gEngfuncs.GetLocalPlayer()->curstate.iuser1 && g_bAlive && fCurrentFOV > 40.0;
}
int g_iRect;
void COverview::EntityESP( void )
{		
	int	iSprWidth = 32;
	int iRect = m_pRect->value;	
	float fRect = m_pRect->value;
	
	/*if (iRect)
		g_iRect = iRect;

	if (fCurrentFOV<=40.0 && g_bAlive)
		m_pRect->value = 0;
	else
		m_pRect->value = g_iRect;*/


	if (strlen(g_szLocation)/* && fCurrentFOV > 40.0*/)
	{
		int iLength, iHeight;
		gEngfuncs.pfnDrawSetTextColor(0.0, 0.8, 0.0);
		gEngfuncs.pfnDrawConsoleStringLen(g_szLocation, &iLength, &iHeight);
		gEngfuncs.pfnDrawConsoleString((iRect -iLength)*0.5, iRect+10, g_szLocation);
	}

	#define OVERBORDER	1
	Tri_Disable(GL_TEXTURE_2D);
	gEngfuncs.pTriAPI->RenderMode(kRenderNormal);
	gEngfuncs.pTriAPI->Color4f(0, 0, 0, 1);
	gEngfuncs.pTriAPI->Begin(TRI_LINES);
	gEngfuncs.pTriAPI->Vertex3f(1, 0, 0);
	gEngfuncs.pTriAPI->Vertex3f(fRect + 1, 1, 0);
	gEngfuncs.pTriAPI->End();
	gEngfuncs.pTriAPI->Begin(TRI_LINES);
	gEngfuncs.pTriAPI->Vertex3f(fRect + 1, 1, 0);
	gEngfuncs.pTriAPI->Vertex3f(fRect + 1, fRect, 0);
	gEngfuncs.pTriAPI->End();
	gEngfuncs.pTriAPI->Begin(TRI_LINES);
	gEngfuncs.pTriAPI->Vertex3f(fRect + 1, fRect, 0);
	gEngfuncs.pTriAPI->Vertex3f(0, fRect, 0);
	gEngfuncs.pTriAPI->End();
	gEngfuncs.pTriAPI->Begin(TRI_LINES);
	gEngfuncs.pTriAPI->Vertex3f(1, fRect, 0);
	gEngfuncs.pTriAPI->Vertex3f(1, 0, 0);
	gEngfuncs.pTriAPI->End();
	Tri_Enable(GL_TEXTURE_2D);

	cl_entity_t *pPlayer = gEngfuncs.GetLocalPlayer();
	cl_entity_t *pEntity = NULL;
	Vector vecForward2, vecRight2;
	float vSub[3],sAng[3];

	int iScale = SCALE;
	int fOut[2];
	int iCallBack; 
	int iLocalIndex = pPlayer->index;
	for (int i = 1; i <= m_iMaxClient; i++)
	{
		iScale = SCALE;
		if(i ==iLocalIndex) continue;
		if(g_iMod == MOD_DM) continue;
		pEntity = gEngfuncs.GetEntityByIndex(i);		
		if(!pEntity) continue;		
				
		if(vPlayer[pEntity->index].fInfectTime > g_flTime && (g_iMod == MOD_ZB || g_iMod == MOD_ZB3)) goto DRAW_ESP;
		if (vPlayer[pEntity->index].team !=vPlayer[iLocalIndex].team)
			continue;
DRAW_ESP:
		if(vPlayer[pEntity->index].killtime < g_flTime)
			continue;
		Tri_Enable(GL_TEXTURE_2D);
		gEngfuncs.pTriAPI->RenderMode(kRenderTransAlpha);
		gEngfuncs.pTriAPI->Color4f(1, 1, 1, 1);
		gEngfuncs.pTriAPI->SpriteTexture(g_pOverview->m_rgpPlayer[vPlayer[i].team-1], 0);

		int iZB = 0;

		if(vPlayer[i].fAudioTime > g_flTime)
		{
			gEngfuncs.pTriAPI->SpriteTexture(g_pOverview->m_pRadio, 0);
			float fSubTime = vPlayer[i].fAudioTime-g_flTime;
			fSubTime -=(int)fSubTime;
			fSubTime-=0.5;
			fSubTime=fabsf(fSubTime);
			iScale =10+15.0*fSubTime;
		}
		else if(vPlayer[i].fInfectTime > g_flTime && (g_iMod == MOD_ZB || g_iMod == MOD_ZB3))
		{
			gEngfuncs.pTriAPI->SpriteTexture(g_pOverview->m_pInfection, 0);
			float fSubTime = vPlayer[i].fInfectTime-g_flTime;
			fSubTime -=(int)fSubTime;
			fSubTime-=0.5;
			fSubTime=fabsf(fSubTime);
			iScale =10+15.0*fSubTime;
			iZB = 1;
		}
		else if(vPlayer[i].fDeathTime > g_flTime)
		{
			gEngfuncs.pTriAPI->SpriteTexture(g_pOverview->m_pDeath, 0);
			float fSubTime = vPlayer[i].fDeathTime-g_flTime;
			fSubTime -=(int)fSubTime;
			fSubTime-=0.5;
			fSubTime=fabsf(fSubTime);
			iScale =10+15.0*fSubTime;
		}

		VectorCopy(pEntity->angles,sAng);

		vSub[1] = gEngfuncs.GetLocalPlayer()->angles[1] - sAng[1];
		vSub[0] = vSub[2] = 0;
		vSub[1] -= 90.0;
		gEngfuncs.pfnAngleVectors(vSub, vecForward2, vecRight2, NULL);
		iCallBack = CalcRadarPoint(iZB?vPlayer[pEntity->index].vLastPos:pEntity->origin,fOut[0],fOut[1],1,iScale);
		if(iCallBack) iScale/=CALC_SCALE;
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->TexCoord2f(1, 0);
		gEngfuncs.pTriAPI->Vertex3f(fOut[0] + vecRight2.x * iScale + vecForward2.x * iScale, fOut[1] + vecRight2.y * iScale + vecForward2.y * iScale, 0);
		gEngfuncs.pTriAPI->TexCoord2f(0, 0);
		gEngfuncs.pTriAPI->Vertex3f(fOut[0] + vecRight2.x * iScale + vecForward2.x * -iScale, fOut[1] + vecRight2.y * iScale + vecForward2.y * -iScale, 0);
		gEngfuncs.pTriAPI->TexCoord2f(0, 1);
		gEngfuncs.pTriAPI->Vertex3f(fOut[0] + vecRight2.x * -iScale + vecForward2.x * -iScale, fOut[1] + vecRight2.y * -iScale + vecForward2.y * -iScale, 0);
		gEngfuncs.pTriAPI->TexCoord2f(1, 1);
		gEngfuncs.pTriAPI->Vertex3f(fOut[0] + vecRight2.x * -iScale + vecForward2.x * iScale, fOut[1] + vecRight2.y * -iScale + vecForward2.y * iScale, 0);
		gEngfuncs.pTriAPI->End();

		if(g_PlayerExtraInfo[i].iFlag & SCOREATTRIB_BOMB)
		{
			iScale = 6;
			gEngfuncs.pTriAPI->SpriteTexture(g_pOverview->m_pBackPack, 0);
			gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			gEngfuncs.pTriAPI->TexCoord2f(1, 0);
			gEngfuncs.pTriAPI->Vertex3f(fOut[0] + vecRight2.x * iScale + vecForward2.x * iScale, fOut[1] + vecRight2.y * iScale + vecForward2.y * iScale, 0);
			gEngfuncs.pTriAPI->TexCoord2f(0, 0);
			gEngfuncs.pTriAPI->Vertex3f(fOut[0] + vecRight2.x * iScale + vecForward2.x * -iScale, fOut[1] + vecRight2.y * iScale + vecForward2.y * -iScale, 0);
			gEngfuncs.pTriAPI->TexCoord2f(0, 1);
			gEngfuncs.pTriAPI->Vertex3f(fOut[0] + vecRight2.x * -iScale + vecForward2.x * -iScale, fOut[1] + vecRight2.y * -iScale + vecForward2.y * -iScale, 0);
			gEngfuncs.pTriAPI->TexCoord2f(1, 1);
			gEngfuncs.pTriAPI->Vertex3f(fOut[0] + vecRight2.x * -iScale + vecForward2.x * iScale, fOut[1] + vecRight2.y * -iScale + vecForward2.y * iScale, 0);
			gEngfuncs.pTriAPI->End();
		}
	}
	if(g_fBombEntityTime > g_flTime && vPlayer[iLocalIndex].team == 2)
	{
		iScale = SCALE;
		pEntity = gEngfuncs.GetEntityByIndex(g_iBombEntity);
		gEngfuncs.pTriAPI->RenderMode(kRenderTransAlpha);
		gEngfuncs.pTriAPI->Color4f(1, 1, 1, 1);
		gEngfuncs.pTriAPI->SpriteTexture(g_pOverview->m_pBackPack, 0);
		VectorCopy(pEntity->angles,sAng);
		vSub[1] = gEngfuncs.GetLocalPlayer()->angles[1] - sAng[1];
		vSub[0] = vSub[2] = 0;
		vSub[1] -= 90.0;

		gEngfuncs.pfnAngleVectors(vSub, vecForward2, vecRight2, NULL);
		iCallBack = CalcRadarPoint(pEntity->origin,fOut[0],fOut[1],1,iScale);
		if(iCallBack) iScale/=CALC_SCALE;
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->TexCoord2f(1, 0);
		gEngfuncs.pTriAPI->Vertex3f(fOut[0] + vecRight2.x * iScale + vecForward2.x * iScale, fOut[1] + vecRight2.y * iScale + vecForward2.y * iScale, 0);
		gEngfuncs.pTriAPI->TexCoord2f(0, 0);
		gEngfuncs.pTriAPI->Vertex3f(fOut[0] + vecRight2.x * iScale + vecForward2.x * -iScale, fOut[1] + vecRight2.y * iScale + vecForward2.y * -iScale, 0);
		gEngfuncs.pTriAPI->TexCoord2f(0, 1);
		gEngfuncs.pTriAPI->Vertex3f(fOut[0] + vecRight2.x * -iScale + vecForward2.x * -iScale, fOut[1] + vecRight2.y * -iScale + vecForward2.y * -iScale, 0);
		gEngfuncs.pTriAPI->TexCoord2f(1, 1);
		gEngfuncs.pTriAPI->Vertex3f(fOut[0] + vecRight2.x * -iScale + vecForward2.x * iScale, fOut[1] + vecRight2.y * -iScale + vecForward2.y * iScale, 0);
		gEngfuncs.pTriAPI->End();
	}
	
	gEngfuncs.pTriAPI->RenderMode(kRenderTransAdd);
	gEngfuncs.pTriAPI->Color4f(1,0.62745f,0, 1.0f);
	gEngfuncs.pTriAPI->SpriteTexture(m_pCamera, 0);
	gEngfuncs.pTriAPI->Begin(TRI_TRIANGLES);
	gEngfuncs.pTriAPI->TexCoord2f(1, 1);
	gEngfuncs.pTriAPI->Vertex3f(fRect/2+CAMETA_BORDER*0.7, fRect/2-CAMETA_BORDER*0.7, 0);
	gEngfuncs.pTriAPI->TexCoord2f(0, 0);
	gEngfuncs.pTriAPI->Vertex3f(fRect/2-CAMETA_BORDER*0.7, fRect/2-CAMETA_BORDER*0.7, 0);
	gEngfuncs.pTriAPI->TexCoord2f(0, 1);
	gEngfuncs.pTriAPI->Vertex3f(fRect/2, fRect/2, 0);
	gEngfuncs.pTriAPI->End(); 
	//

	cl_entity_t *pEntity2 = NULL;
	for (int i = 1; i <= 32; i++)
	{
		if(i ==iLocalIndex || g_iMod == MOD_NONE || g_iMod == MOD_ZB || g_iMod == MOD_ZB3 || g_iMod == MOD_TDM || g_iMod == MOD_GD) continue;
		pEntity2 = gEngfuncs.GetEntityByIndex(i);
		if(!pEntity2) continue;
		if(g_iMod == MOD_DM) continue;
		
		if (vPlayer[pEntity2->index].team !=vPlayer[iLocalIndex].team)
			continue;
		if(vPlayer[pEntity2->index].killtime < g_flTime)
			continue;
		if(pCvar_Name->value)
		{
			Vector pPos = vPlayer[i].info->origin;
			pPos[2] += 30.0;
			float vecScreen[2];
			if(CalcScreen(pPos,vecScreen))
			{
				hud_player_info_t hPlayer;
				gEngfuncs.pfnGetPlayerInfo(i,&hPlayer);
				Fonts_SetColor(255,255,255,100);
				Fonts_SetSize(16,16);
				wchar_t *name;
				name = UTF8ToUnicode(hPlayer.name);
				Fonts_Draw(name,vecScreen[0]-Fonts_GetLen(name)/2,vecScreen[1],500,100);
			}
		}
	}
	if(g_iMod == MOD_ZB3/* && vPlayer[gEngfuncs.GetLocalPlayer()->index].team != 2*/ && pCvar_TipIcon->value)
	{
		for(int i=34;i<512;i++)
		{
			cl_entity_s *pEnt = gEngfuncs.GetEntityByIndex(i);
			if(pEnt && pEnt->curstate.fuser1 > g_flTime)
			{
				float vecScreen[2];
				if(pEnt->curstate.iuser1 == 1 && vPlayer[gEngfuncs.GetLocalPlayer()->index].team != 2)
				{
					if(CalcScreen(pEnt->origin,vecScreen))
					{
						MH_DrawTGAFunction(g_Texture[g_zb3_tga_icon_supply].iTexture,255,255,255,255,vecScreen[0] - g_Texture[g_zb3_tga_icon_supply].iWidth / 2,vecScreen[1] - g_Texture[g_zb3_tga_icon_supply].iHeight / 2 - 5,1.0);

						/*Tri_Enable(GL_TEXTURE_2D);
						Tri_BindTexture(GL_TEXTURE_2D,g_MHTga[g_zb3_tga_icon_supply].texid);
						if(g_iVideoMode) glColor4ub(255,255,255,255);
						else gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
						Tri_Enable(GL_BLEND);
						Tri_Enable(GL_ALPHA_TEST);
						Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 

						gEngfuncs.pTriAPI->Begin(TRI_QUADS);
						gEngfuncs.pTriAPI->TexCoord2f(0,1);
						gEngfuncs.pTriAPI->Vertex3f(vecScreen[0],vecScreen[1]+g_MHTga[g_zb3_tga_icon_supply].height,0);
						gEngfuncs.pTriAPI->TexCoord2f(1,1);
						gEngfuncs.pTriAPI->Vertex3f(vecScreen[0]+g_MHTga[g_zb3_tga_icon_supply].width,vecScreen[1]+g_MHTga[g_zb3_tga_icon_supply].height,0);		
						gEngfuncs.pTriAPI->TexCoord2f(1,0);
						gEngfuncs.pTriAPI->Vertex3f(vecScreen[0]+g_MHTga[g_zb3_tga_icon_supply].width,vecScreen[1],0);		
						gEngfuncs.pTriAPI->TexCoord2f(0,0); 
						gEngfuncs.pTriAPI->Vertex3f(vecScreen[0],vecScreen[1],0);
						gEngfuncs.pTriAPI->End();*/

						Vector vOriDis;

						VectorSubtract(gEngfuncs.GetLocalPlayer()->origin,pEnt->origin,vOriDis);
						float distance = sqrt(vOriDis.x*vOriDis.x+vOriDis.y*vOriDis.y+vOriDis.z*vOriDis.z)/40.0f;
						char p1[256];
						wchar_t p2[256];
						sprintf(p1,"[%dm]",(short int)distance);

						Fonts_C2W(p2,255,p1);
						Fonts_SetColor(157,248,255,255);
						Fonts_SetSize(16,16);
						Fonts_Draw(p2,int(vecScreen[0]-Fonts_GetLen(p2)/2+1),vecScreen[1]+g_Texture[g_zb3_tga_icon_supply].iHeight / 2+20 - 5,100,100);
						
						// Radar
					}
					gEngfuncs.pTriAPI->RenderMode(kRenderNormal);
					int fOut[2];
					Tri_Enable(GL_TEXTURE_2D);
					g_pOverview->CalcRadarPoint(pEnt->origin,fOut[0],fOut[1],1,6);
					gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_supply),133,247,255);
					gEngfuncs.pfnSPR_DrawAdditive(0,fOut[0],fOut[1],&GetSpriteRect(g_zb3_spr_supply));
					gEngfuncs.pTriAPI->RenderMode(kRenderNormal);
				}
				else if(pEnt->curstate.iuser1 == 2 && vPlayer[gEngfuncs.GetLocalPlayer()->index].team == 2 && pEnt->curstate.iuser4 == 1)
				{					
					if(CalcScreen(pEnt->origin,vecScreen))
					{
						MH_DrawTGAFunction(g_Texture[g_zb3_tga_icon_trap].iTexture,255,255,255,255,vecScreen[0] - g_Texture[g_zb3_tga_icon_trap].iWidth / 2,vecScreen[1] - g_Texture[g_zb3_tga_icon_trap].iHeight / 2,1.0);
						/*Tri_Enable(GL_TEXTURE_2D);
						Tri_BindTexture(GL_TEXTURE_2D,g_MHTga[g_zb3_tga_icon_trap].texid);
						if(g_iVideoMode) glColor4ub(255,255,255,255);
						else gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
						Tri_Enable(GL_BLEND);
						Tri_Enable(GL_ALPHA_TEST);
						Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 

						gEngfuncs.pTriAPI->Begin(TRI_QUADS);
						gEngfuncs.pTriAPI->TexCoord2f(0,1);
						gEngfuncs.pTriAPI->Vertex3f(vecScreen[0],vecScreen[1]+g_MHTga[g_zb3_tga_icon_trap].height,0);
						gEngfuncs.pTriAPI->TexCoord2f(1,1);
						gEngfuncs.pTriAPI->Vertex3f(vecScreen[0]+g_MHTga[g_zb3_tga_icon_trap].width,vecScreen[1]+g_MHTga[g_zb3_tga_icon_trap].height,0);		
						gEngfuncs.pTriAPI->TexCoord2f(1,0);
						gEngfuncs.pTriAPI->Vertex3f(vecScreen[0]+g_MHTga[g_zb3_tga_icon_trap].width,vecScreen[1],0);		
						gEngfuncs.pTriAPI->TexCoord2f(0,0); 
						gEngfuncs.pTriAPI->Vertex3f(vecScreen[0],vecScreen[1],0);
						gEngfuncs.pTriAPI->End();*/

						Vector vOriDis;

						VectorSubtract(gEngfuncs.GetLocalPlayer()->origin,pEnt->origin,vOriDis);
						float distance = sqrt(vOriDis.x*vOriDis.x+vOriDis.y*vOriDis.y+vOriDis.z*vOriDis.z)/40.0f;
						char p1[256];
						wchar_t p2[256];
						sprintf(p1,"[%dm]",(short int)distance);

						Fonts_C2W(p2,255,p1);
						Fonts_SetColor(255,203,125,255);
						Fonts_SetSize(14,14);
						Fonts_Draw(p2,int(vecScreen[0]-Fonts_GetLen(p2)/2+2),vecScreen[1]+g_Texture[g_zb3_tga_icon_trap].iHeight/2+25,100,100);
						
					}
				}
			}
		} 
	}
	gEngfuncs.pTriAPI->RenderMode(kRenderNormal);
}