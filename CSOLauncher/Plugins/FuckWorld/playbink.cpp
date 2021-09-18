#include "base.h"
#include "bink.h"
#include "BaseUI.h"
static int iPlaying = 0;
static float fStartTime = 0;
static int iFrame = 0;
static int iBinkTextureID = 0;
static HBINK hBink;
int Bink_iX,Bink_iY,Bink_iCenter;
int BinkColor[3];
int iBinkLoop = 0;
int iBinkStop = 0;
int iBinkIsScope = 0;
int iBinkScopeStop = 0;
// 
BYTE *pBinkMem = NULL;
void PlayBinkInstant(char *pszName,int iStop,int iLoop)
{
	if(!iBinkTextureID)
		iBinkTextureID = g_pSurface->CreateNewTextureID();
	
	if(pCvar_DrawBink->value <1)
	{
		LogToFile("[Bink]尝试播放%s 但是被Cvar阻止",pszName);
		return;
	}

	if(!iPlaying)
	{
		// Clear Mem
		if(pBinkMem)
		{
			LogToFile("[Bink]释放内存空间");
			free(pBinkMem);
			pBinkMem = NULL;
		}
		hBink = BinkOpen(pszName,135266304);
		if(!hBink)
		{
			LogToFile("[Bink]加载BIK文件失败： %s",pszName);
			return;
		}
		fStartTime = 0;
		iFrame = 1;
		iPlaying = 1;
		iBinkLoop = iLoop;
		iBinkStop = iStop;
		if(strstr(pszName,"scope"))
		{
			iBinkIsScope = 1;
			iFrame = 60; // skip some frames
		}
		else iBinkIsScope = 0;
		// Alloc Memory
		int iPixelSize = 4 * hBink->Width * hBink->Height;
		pBinkMem = (BYTE *)malloc(iPixelSize);
		if(pBinkMem)
			LogToFile("[Bink]申请内存空间:%d",iPixelSize);
		else LogToFile("[Bink]申请内存空间失败!");
	}
	else
	{
		if(iStop) iPlaying = 0;
	}
}
void BinkSetPos(int X,int Y,int Center)
{
	Bink_iX = X;
	Bink_iY = Y;
	Bink_iCenter = Center;
}
void BinkSetColor(int R,int G,int B)
{
	BinkColor[0] = R;
	BinkColor[1] = G;
	BinkColor[2] = B;
}
void BinkRedraw2(void)
{
	if(!iPlaying) return;
	if(iBinkStop && iBinkLoop)
	{
		iBinkLoop = 0;
		iPlaying = 0;
		iBinkStop = 0;
		return;
	}

	if(g_flTime - fStartTime > ( float(hBink->FrameRateDiv)/ float(hBink->FrameRate))) 
	{ 
		if(iBinkIsScope)
		{
			if(!g_BinkScopeColor)
			{
				goto SKIP_FRAME;
			}
		}
		iFrame ++;
SKIP_FRAME:
		fStartTime = g_flTime;
		if(iFrame> hBink->Frames)
		{
			if(!iBinkLoop)
			{
				iPlaying = 0;
				BinkClose(hBink);
				return;
			}
			else
			{
				iFrame = 1;
			}
		}
		BinkGoto(hBink, iFrame, 0);
		BinkCopyToBuffer(hBink, pBinkMem, hBink->Width * 4, hBink->Height, 0, 0, BINKSURFACE32RA);
		Tri_BindTexture(GL_TEXTURE_2D, iBinkTextureID);
		Tri_SetTextureParam();		
		Tri_TexImage2D(GL_TEXTURE_2D, 0, 4, hBink->Width, hBink->Height, 0, GL_RGBA, GL_UNSIGNED_BYTE, pBinkMem);
	}
	int iX ,iY,iWidth,iHeight;
	iWidth = hBink->Width;
	iHeight = hBink->Height;

	if(Bink_iCenter)
	{
		iX = Bink_iX - iWidth/2;
		iY = Bink_iY - iHeight/2;
	}
	else
	{
		iX = Bink_iX ;
		iY = Bink_iY ;
	}
	float LENGTH_SCOPE = g_sScreenInfo.iWidth / 3.3;
	if(iBinkIsScope && fCurrentFOV<=40.0)
	{
		if(!g_BinkScopeColor)
		{
			BinkColor[0] = 171;
			BinkColor[1] = 89 ;
			BinkColor[2] = 78;
			// LOCKED!
	#define LENGTH_SCOPE_TARGET	120
#define	LENGTH_SCOPE_BORDER	75

			Tri_Enable(GL_TEXTURE_2D);
			Tri_Enable(GL_BLEND);
			Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 			

			Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_tga_Scope_Target].texid);
			if(g_iVideoMode)
			{
				glColor4ub(255,255,255,255);
			}
			else gEngfuncs.pTriAPI->Color4ub(255,255,255,255);

			gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			gEngfuncs.pTriAPI->TexCoord2f(0,1);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 - LENGTH_SCOPE_TARGET,g_sScreenInfo.iHeight/2 - LENGTH_SCOPE_BORDER, 0);

			gEngfuncs.pTriAPI->TexCoord2f(1,1);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 - LENGTH_SCOPE_BORDER,g_sScreenInfo.iHeight/2 - LENGTH_SCOPE_BORDER,0);
				
			gEngfuncs.pTriAPI->TexCoord2f(1,0);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 - LENGTH_SCOPE_BORDER,g_sScreenInfo.iHeight/2 - LENGTH_SCOPE_TARGET,0);
				
			gEngfuncs.pTriAPI->TexCoord2f(0,0);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 - LENGTH_SCOPE_TARGET,g_sScreenInfo.iHeight/2 - LENGTH_SCOPE_TARGET,0);
			gEngfuncs.pTriAPI->End();
				// 2
			gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			gEngfuncs.pTriAPI->TexCoord2f(0,1);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 + LENGTH_SCOPE_TARGET,g_sScreenInfo.iHeight/2 - LENGTH_SCOPE_BORDER, 0);

			gEngfuncs.pTriAPI->TexCoord2f(1,1);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 + LENGTH_SCOPE_BORDER,g_sScreenInfo.iHeight/2  - LENGTH_SCOPE_BORDER,0);
				
			gEngfuncs.pTriAPI->TexCoord2f(1,0);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 + LENGTH_SCOPE_BORDER,g_sScreenInfo.iHeight/2 - LENGTH_SCOPE_TARGET,0);
				
			gEngfuncs.pTriAPI->TexCoord2f(0,0);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 + LENGTH_SCOPE_TARGET,g_sScreenInfo.iHeight/2 - LENGTH_SCOPE_TARGET,0);
			gEngfuncs.pTriAPI->End();
				// 3
			gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			gEngfuncs.pTriAPI->TexCoord2f(0,1);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 - LENGTH_SCOPE_TARGET,g_sScreenInfo.iHeight/2 + LENGTH_SCOPE_BORDER , 0);

			gEngfuncs.pTriAPI->TexCoord2f(1,1);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 - LENGTH_SCOPE_BORDER,g_sScreenInfo.iHeight/2 + LENGTH_SCOPE_BORDER,0);
				
			gEngfuncs.pTriAPI->TexCoord2f(1,0);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 - LENGTH_SCOPE_BORDER,g_sScreenInfo.iHeight/2 + LENGTH_SCOPE_TARGET,0);
				
			gEngfuncs.pTriAPI->TexCoord2f(0,0);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 - LENGTH_SCOPE_TARGET,g_sScreenInfo.iHeight/2 + LENGTH_SCOPE_TARGET,0);
			gEngfuncs.pTriAPI->End();
				// 4
			gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			gEngfuncs.pTriAPI->TexCoord2f(0,1);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 + LENGTH_SCOPE_BORDER,g_sScreenInfo.iHeight/2+LENGTH_SCOPE_TARGET, 0);

			gEngfuncs.pTriAPI->TexCoord2f(1,1);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 + LENGTH_SCOPE_BORDER,g_sScreenInfo.iHeight/2 + LENGTH_SCOPE_BORDER,0);
				
			gEngfuncs.pTriAPI->TexCoord2f(1,0); 
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2+LENGTH_SCOPE_TARGET,g_sScreenInfo.iHeight/2+ LENGTH_SCOPE_BORDER,0);
				
			gEngfuncs.pTriAPI->TexCoord2f(0,0);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 + LENGTH_SCOPE_TARGET,g_sScreenInfo.iHeight/2+LENGTH_SCOPE_TARGET,0);
			gEngfuncs.pTriAPI->End();
		}
		else
		{
			BinkColor[0] = 84;
			BinkColor[1] = 135;
			BinkColor[2] = 130;

		}
		// Draw SCOPR
		// 1024 -- 240
		// 800  -- 187.5
		
//#define LENGTH_SCOPE	240

		Tri_Enable(GL_TEXTURE_2D);
		Tri_Enable(GL_BLEND);
		Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
		

		Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_tga_Scope].texid);
		if(g_iVideoMode)
		{
			glColor4ub(255,255,255,255);
		}
		else gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
		
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->TexCoord2f(0,1);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 - LENGTH_SCOPE,g_sScreenInfo.iHeight/2, 0);

		gEngfuncs.pTriAPI->TexCoord2f(1,1);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);
			
		gEngfuncs.pTriAPI->TexCoord2f(1,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2 - LENGTH_SCOPE,0);
			
		gEngfuncs.pTriAPI->TexCoord2f(0,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 - LENGTH_SCOPE,g_sScreenInfo.iHeight/2 - LENGTH_SCOPE,0);
		gEngfuncs.pTriAPI->End();
			// 2
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->TexCoord2f(0,1);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 + LENGTH_SCOPE,g_sScreenInfo.iHeight/2, 0);

		gEngfuncs.pTriAPI->TexCoord2f(1,1);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);
			
		gEngfuncs.pTriAPI->TexCoord2f(1,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2 - LENGTH_SCOPE,0);
			
		gEngfuncs.pTriAPI->TexCoord2f(0,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 + LENGTH_SCOPE,g_sScreenInfo.iHeight/2 - LENGTH_SCOPE,0);
		gEngfuncs.pTriAPI->End();
			// 3
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->TexCoord2f(0,1);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 - LENGTH_SCOPE,g_sScreenInfo.iHeight/2, 0);

		gEngfuncs.pTriAPI->TexCoord2f(1,1);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);
			
		gEngfuncs.pTriAPI->TexCoord2f(1,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2 + LENGTH_SCOPE,0);
			
		gEngfuncs.pTriAPI->TexCoord2f(0,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 - LENGTH_SCOPE,g_sScreenInfo.iHeight/2 + LENGTH_SCOPE,0);
		gEngfuncs.pTriAPI->End();
			// 4
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->TexCoord2f(0,1);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2+LENGTH_SCOPE, 0);

		gEngfuncs.pTriAPI->TexCoord2f(1,1);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);
			
		gEngfuncs.pTriAPI->TexCoord2f(1,0); 
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2+LENGTH_SCOPE,g_sScreenInfo.iHeight/2,0);
			
		gEngfuncs.pTriAPI->TexCoord2f(0,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 + LENGTH_SCOPE,g_sScreenInfo.iHeight/2+LENGTH_SCOPE,0);
		gEngfuncs.pTriAPI->End();

	}

	Tri_Enable(GL_TEXTURE_2D);
	Tri_Enable(GL_BLEND);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	Tri_BindTexture(GL_TEXTURE_2D, iBinkTextureID);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
	gEngfuncs.pTriAPI->Color4ub(BinkColor[0],BinkColor[1],BinkColor[2],255);
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY+iHeight,0);
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iX+iWidth,iY+iHeight,0);
	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iX+iWidth,iY,0);
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
	gEngfuncs.pTriAPI->End();

	// Black Side
	if(iBinkIsScope && 0.0 < fCurrentFOV && fCurrentFOV<=40.0)
	{
		
		/*if(g_iVideoMode)
		{
			glColor4ub(0,0,0,255);
		}
		else gEngfuncs.pTriAPI->Color4ub(0,0,0,255);
		Tri_Disable(GL_TEXTURE_2D);
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->Vertex3f(0,0,0);
		gEngfuncs.pTriAPI->Vertex3f(0,g_sScreenInfo.iHeight/2 - LENGTH_SCOPE,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2 - LENGTH_SCOPE,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,0,0);
		gEngfuncs.pTriAPI->End();

		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->Vertex3f(0,0,0);
		gEngfuncs.pTriAPI->Vertex3f(0,g_sScreenInfo.iHeight,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 - LENGTH_SCOPE,g_sScreenInfo.iHeight,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 - LENGTH_SCOPE,0,0);
		gEngfuncs.pTriAPI->End();

		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 + LENGTH_SCOPE,0,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2 + LENGTH_SCOPE,g_sScreenInfo.iHeight,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,g_sScreenInfo.iHeight,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,0,0);
		gEngfuncs.pTriAPI->End();

		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->Vertex3f(0,g_sScreenInfo.iHeight/2+LENGTH_SCOPE,0);
		gEngfuncs.pTriAPI->Vertex3f(0,g_sScreenInfo.iHeight,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,g_sScreenInfo.iHeight,0);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2+LENGTH_SCOPE,0);
		gEngfuncs.pTriAPI->End();*/
	}
}
