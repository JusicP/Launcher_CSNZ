#include "base.h"

int g_retina[8];
int g_retina_draw[8];
int g_retina_full[8];
int g_retina_flash[8];
float g_retina_endtime[8];


void DrawRetinaReset()
{
	memset(g_retina,0,sizeof(g_retina));
	memset(g_retina_draw,0,sizeof(g_retina_draw));
	memset(g_retina_full,0,sizeof(g_retina_full));
	memset(g_retina_flash,0,sizeof(g_retina_flash));
	memset(g_retina_endtime,0,sizeof(g_retina_endtime));
}
void DrawRetina(void)
{
	if(!g_bAlive) return;
	for(int i=0;i<=7;i++)
	{
		if(!g_retina_draw[i]) continue;

		if(g_retina_endtime[i]<g_flTime)
		{
			g_retina_draw[i] = 0;
			continue;
		}

		float alpha;
	
		Tri_Enable(GL_BLEND);
		Tri_Enable(GL_ALPHA_TEST);
		Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
		Tri_AlphaFunc(GL_GREATER, 0.0);

		Tri_Enable(GL_TEXTURE_2D);
		Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_retina[i]].texid);	

		float fSubTime = g_flTime;
		fSubTime -=(int)fSubTime;
		fSubTime -= 0.5;
		fSubTime= fabsf(fSubTime);	
		alpha = fSubTime+0.5;

		alpha *= 255;

		if(!g_retina_flash[i]) alpha = 255;

		if(g_iVideoMode) glColor4ub(255,255,255,alpha);
		else gEngfuncs.pTriAPI->Color4ub(255,255,255,alpha);

		
		
		if(!g_retina_full[i])
		{
			float fX = 0.05f;
			float fY = 0.95f;

			gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
			gEngfuncs.pTriAPI->TexCoord2f(fX,1-fX );
			gEngfuncs.pTriAPI->Vertex3f(0,g_sScreenInfo.iHeight/2,0);
			gEngfuncs.pTriAPI->TexCoord2f(fY,1-fX);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);		
			gEngfuncs.pTriAPI->TexCoord2f(fY,1-fY);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,0,0);
		
			gEngfuncs.pTriAPI->TexCoord2f(fX,1-fY);
			gEngfuncs.pTriAPI->Vertex3f(0,0,0);
			gEngfuncs.pTriAPI->End();
			//
			gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			gEngfuncs.pTriAPI->TexCoord2f(fX,1-fX);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,0,0);
			gEngfuncs.pTriAPI->TexCoord2f(fY,1-fX);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);		
			gEngfuncs.pTriAPI->TexCoord2f(fY,1-fY);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2,0);
			gEngfuncs.pTriAPI->TexCoord2f(fX,1-fY);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,0,0);
			gEngfuncs.pTriAPI->End();
			//
			gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			gEngfuncs.pTriAPI->TexCoord2f(fX,1-fX);
			gEngfuncs.pTriAPI->Vertex3f(0,g_sScreenInfo.iHeight/2,0);
			gEngfuncs.pTriAPI->TexCoord2f(fY,1-fX);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);		
			gEngfuncs.pTriAPI->TexCoord2f(fY,1-fY);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight,0);
			gEngfuncs.pTriAPI->TexCoord2f(fX,1-fY);
			gEngfuncs.pTriAPI->Vertex3f(0,g_sScreenInfo.iHeight,0);
			gEngfuncs.pTriAPI->End();
			//
			gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			gEngfuncs.pTriAPI->TexCoord2f(fX,1-fX);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight,0);
			gEngfuncs.pTriAPI->TexCoord2f(fY,1-fX);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);		
			gEngfuncs.pTriAPI->TexCoord2f(fY,1-fY);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2,0);
			gEngfuncs.pTriAPI->TexCoord2f(fX,1-fY);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,g_sScreenInfo.iHeight,0);
			gEngfuncs.pTriAPI->End();
		}
		else
		{
			
			gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			
			gEngfuncs.pTriAPI->TexCoord2f(0,0);
			gEngfuncs.pTriAPI->Vertex3f(0,g_sScreenInfo.iHeight,0);
			gEngfuncs.pTriAPI->TexCoord2f(1,0);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,g_sScreenInfo.iHeight,0);
			gEngfuncs.pTriAPI->TexCoord2f(1,1);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,0,0);
			
			gEngfuncs.pTriAPI->TexCoord2f(0,1);
			gEngfuncs.pTriAPI->Vertex3f(0,0,0);
			gEngfuncs.pTriAPI->End();
		}
	}
}

void DrawRetinaParseData(int index, int iDraw, int iFullScreen, int iFlash, int iChan, float fTime)
{	
	g_retina[iChan] = index;	
	g_retina_draw[iChan] = iDraw;
	g_retina_full[iChan] = iFullScreen;	
	g_retina_flash[iChan] = iFlash;
	g_retina_endtime[iChan] = fTime;
}