#include "base.h"
DrawIconItem g_DrawIcon[DRAWICON_MAX+1];
int g_Display;
int g_Tga_SpBox;
int g_Tga_SpuBox;
int g_Tga_BombA;
int g_Tga_BombB;

void DrawIconInitialize(void)
{
	memset(g_DrawIcon, 0, sizeof(g_DrawIcon));
	g_Display = 1;
}
void DrawIconAdd(DrawIconItem rgTempDrawIcon)
{
	if (rgTempDrawIcon.iChannel <= 0 || rgTempDrawIcon.iChannel >= DRAWICON_MAX)
	{
		for (int i = 1; i < DRAWICON_MAX; i++)
		{
			if (!g_DrawIcon[i].iChannel)
			{
				g_DrawIcon[i] = rgTempDrawIcon;
				break;
			}
		}
	}
	else
		g_DrawIcon[rgTempDrawIcon.iChannel] = rgTempDrawIcon;
}

void DrawFollowIcon()
{
	int iColor =(int)pCvar_TipIcon->value;
	
	for(int j = 1;j < (DRAWICON_MAX+1) ; j++)
	{
		Vector vPlayerPos ;
		VectorCopy(gEngfuncs.GetLocalPlayer()->origin,vPlayerPos);
		if(!g_Display) return;
		if(!g_DrawIcon[j].iChannel) continue;
		if(!g_DrawIcon[j].iToggle) continue;
		
		
		float vecScreen[2];

		vec3_t EntViewOrg;
		EntViewOrg[0] = (float)g_DrawIcon[j].x;
		EntViewOrg[1] = (float)g_DrawIcon[j].y;
		EntViewOrg[2] = (float)g_DrawIcon[j].z;

		if(!g_DrawIcon[j].iBox) g_DrawIcon[j].hl_hSprites = GetSprite(g_DrawIcon[j].iSprIndex);

		if(CalcScreen(EntViewOrg,vecScreen))
		{				
			if(g_DrawIcon[j].iBox == 1 && iColor)
			{
				glEnable(GL_TEXTURE_2D);
				glBindTexture(GL_TEXTURE_2D, g_iMod==MOD_ZB?g_MHTga[g_Tga_SpBox].texid:g_MHTga[g_Tga_SpuBox].texid);
				glColor4f(1,1,1,1);
				glEnable(GL_BLEND);
				glEnable(GL_ALPHA_TEST);
				glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 

				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0],vecScreen[1]+g_MHTga[g_Tga_SpBox].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0]+g_MHTga[g_Tga_SpBox].width,vecScreen[1]+g_MHTga[g_Tga_SpBox].height,0);		
				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0]+g_MHTga[g_Tga_SpBox].width,vecScreen[1],0);		
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0],vecScreen[1],0);
				gEngfuncs.pTriAPI->End();
				glDisable(GL_BLEND);
				glDisable(GL_ALPHA_TEST);
			}
			else if(g_DrawIcon[j].iBox == 2) //BombA
			{
				if(!iColor) continue;
				MH_DrawTGAFunction(g_Texture[g_Tga_BombA].iTexture,255,255,255,255,vecScreen[0],vecScreen[1],1.0);
				/*Tri_Enable(GL_TEXTURE_2D);
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_Tga_BombA].texid);
				gEngfuncs.pTriAPI->Color4f(1,1,1,1);
				Tri_Enable(GL_BLEND);
				Tri_Enable(GL_ALPHA_TEST);
				Tri_AlphaFunc(GL_GREATER, 0.0);
				Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 

				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0],vecScreen[1]+g_MHTga[g_Tga_BombA].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0]+g_MHTga[g_Tga_BombA].width,vecScreen[1]+g_MHTga[g_Tga_BombA].height,0);		
				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0]+g_MHTga[g_Tga_BombA].width,vecScreen[1],0);		
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0],vecScreen[1],0);
				gEngfuncs.pTriAPI->End();*/
			}
			else if(g_DrawIcon[j].iBox == 3 ) //BombB
			{
				if(!iColor) continue;
				MH_DrawTGAFunction(g_Texture[g_Tga_BombB].iTexture,255,255,255,255,vecScreen[0],vecScreen[1],1.0);
				/*Tri_Enable(GL_TEXTURE_2D);
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_Tga_BombB].texid);
				gEngfuncs.pTriAPI->Color4f(1,1,1,1);
				Tri_Enable(GL_BLEND);
				Tri_Enable(GL_ALPHA_TEST);
				Tri_AlphaFunc(GL_GREATER, 0.0);
				Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 

				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0],vecScreen[1]+g_MHTga[g_Tga_BombB].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0]+g_MHTga[g_Tga_BombB].width,vecScreen[1]+g_MHTga[g_Tga_BombB].height,0);		
				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0]+g_MHTga[g_Tga_BombB].width,vecScreen[1],0);		
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0],vecScreen[1],0);
				gEngfuncs.pTriAPI->End();*/
			}
			else
			{
				gEngfuncs.pfnSPR_Set(g_DrawIcon[j].hl_hSprites,g_DrawIcon[j].r,g_DrawIcon[j].g,g_DrawIcon[j].b);
				gEngfuncs.pfnSPR_DrawAdditive(0,vecScreen[0], vecScreen[1], &GetSpriteRect(g_DrawIcon[j].iSprIndex));
			}
			if(g_DrawIcon[j].iDistance)
			{
				
				VectorSubtract(vPlayerPos,EntViewOrg,vPlayerPos);

				float distance = sqrt(vPlayerPos.x*vPlayerPos.x+vPlayerPos.y*vPlayerPos.y+vPlayerPos.z*vPlayerPos.z)/40.0f;
				char p1[256];
				wchar_t p2[256];
				sprintf(p1,"[%dm]",(short int)distance);

				Fonts_C2W(p2,255,p1);

				if(g_DrawIcon[j].iChannel<9)
				{
					Fonts_SetColor(251,201,96,255);
					Fonts_SetSize(16,16);
					if(g_DrawIcon[j].iBox == 2 || g_DrawIcon[j].iBox == 3)
						Fonts_Draw(p2,int(vecScreen[0]+g_Texture[g_Tga_BombA].iWidth/2-Fonts_GetLen(p2)/2 + 2),vecScreen[1]+g_Texture[g_Tga_BombB].iHeight+20,120,30);
					else
						Fonts_Draw(p2,vecScreen[0],vecScreen[1]+g_MHTga[g_Tga_SpBox].height+2,80,30);

				}
			}
		}
	}
}
