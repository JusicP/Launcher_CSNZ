#include "base.h"

DrawFontTextItem g_rgDrawFontText[MAX_DRAWFONTTEXT];
int m_TextBg_Right,m_TextBg_Left,m_TextBg_Center;

void DrawFontTextInitialize(void)
{
	memset(g_rgDrawFontText, 0, sizeof(g_rgDrawFontText));
	m_TextBg_Right = FindTexture("resource\\hud\\other\\textbg_right");
	m_TextBg_Left = FindTexture("resource\\hud\\other\\textbg_left");
	m_TextBg_Center = FindTexture("resource\\hud\\other\\textbg_center");
}

void DrawFontTextAdd(DrawFontTextItem rgTempDrawText)
{
	if (rgTempDrawText.iChanne <= 0 || rgTempDrawText.iChanne >= MAX_DRAWFONTTEXT)
	{
		for (int i = 0; i < MAX_DRAWFONTTEXT; i++)
		{
			if (!g_rgDrawFontText[i].flDisplayTime)
			{
				g_rgDrawFontText[i] = rgTempDrawText;
				break;
			}
		}
	}
	else
		g_rgDrawFontText[rgTempDrawText.iChanne] = rgTempDrawText;
}

void DrawFontTextRedraw()
{
	for (int i = 0; i < MAX_DRAWFONTTEXT; i++)
	{
		if (!g_rgDrawFontText[i].flDisplayTime)
			continue;

		if (g_flTime > g_rgDrawFontText[i].flDisplayTime)
		{
			g_rgDrawFontText[i].flDisplayTime = 0.0;
			continue;
		}
		int iAlpha;
		// Set Color
		if(g_rgDrawFontText[i].fFadeTime < 0.1f)
		{
			iAlpha = 255;
		}
		else
		{
			float fDes = g_flTime - g_rgDrawFontText[i].flStartTime;
			if(fDes < g_rgDrawFontText[i].fFadeTime)
			{
				// Set Alpha
				iAlpha = min(255,fDes / g_rgDrawFontText[i].fFadeTime * 255);
			}
			else if(g_rgDrawFontText[i].flDisplayTime - g_flTime<g_rgDrawFontText[i].fFadeTime)
			{
				float iLess = g_rgDrawFontText[i].flDisplayTime - g_flTime;
				iAlpha = iLess / g_rgDrawFontText[i].fFadeTime * 255;
			}
			else iAlpha = 255;
		}
		Fonts_SetSize(g_rgDrawFontText[i].iScale,g_rgDrawFontText[i].iScale);
		Fonts_SetColor(g_rgDrawFontText[i].color.r,g_rgDrawFontText[i].color.g,g_rgDrawFontText[i].color.b,iAlpha);
		wchar_t *pText;
		pText = UTF8ToUnicode(g_rgDrawFontText[i].szText);
		int iLen = Fonts_GetLen(pText);
		// Add Bg
		if(g_rgDrawFontText[i].iFillBg)
		{
			/*Tri_Enable(GL_BLEND);
			Tri_BlendFunc(GL_SRC_ALPHA,GL_ONE_MINUS_SRC_ALPHA);
			Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[m_TextBg_Left].texid);
			if(g_iVideoMode)
			{
				glColor4ub(255,255,255,iAlpha);
			}
			else gEngfuncs.pTriAPI->Color4ub(255,255,255,iAlpha);*/
			static int iX,iY;
			iX = g_sScreenInfo.iWidth * 0.15;
			iY = g_rgDrawFontText[i].y - 5 - iWidthCheck;
			// Left
			MH_DrawTGAFunction2(g_Texture[m_TextBg_Left].iTexture,iX,iY,g_Texture[m_TextBg_Left].iWidth,20 + iWidthCheck, iAlpha);
			/*gEngfuncs.pTriAPI->Begin(TRI_QUADS);	
			gEngfuncs.pTriAPI->TexCoord2f(0,1);
			gEngfuncs.pTriAPI->Vertex3f(iX,iY+iWidthCheck + 20,0);
			gEngfuncs.pTriAPI->TexCoord2f(1,1);
			gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[m_TextBg_Left].width,iY+iWidthCheck + 20,0);
			gEngfuncs.pTriAPI->TexCoord2f(1,0);
			gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[m_TextBg_Left].width,iY,0);
			gEngfuncs.pTriAPI->TexCoord2f(0,0);
			gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
			gEngfuncs.pTriAPI->End();*/
			// Center
			iX +=g_Texture[m_TextBg_Right].iWidth;
			MH_DrawTGAFunction2(g_Texture[m_TextBg_Center].iTexture,iX,iY,g_sScreenInfo.iWidth*0.85-g_Texture[m_TextBg_Right].iWidth-iX,20 + iWidthCheck, iAlpha);
			/*Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[m_TextBg_Center].texid);
			gEngfuncs.pTriAPI->Begin(TRI_QUADS);	
			gEngfuncs.pTriAPI->TexCoord2f(0,1);
			gEngfuncs.pTriAPI->Vertex3f(iX,iY+iWidthCheck + 20,0);
			gEngfuncs.pTriAPI->TexCoord2f(1,1);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth*0.85-g_MHTga[m_TextBg_Right].width,iY+iWidthCheck + 20,0);
			gEngfuncs.pTriAPI->TexCoord2f(1,0);
			gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth*0.85-g_MHTga[m_TextBg_Right].width,iY,0);
			gEngfuncs.pTriAPI->TexCoord2f(0,0);
			gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
			gEngfuncs.pTriAPI->End();*/
			// Right
			iX =g_sScreenInfo.iWidth*0.85-g_Texture[m_TextBg_Right].iWidth;
			MH_DrawTGAFunction2(g_Texture[m_TextBg_Right].iTexture,iX,iY,g_Texture[m_TextBg_Right].iWidth,20 + iWidthCheck, iAlpha);
			/*Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[m_TextBg_Right].texid);
			gEngfuncs.pTriAPI->Begin(TRI_QUADS);	
			gEngfuncs.pTriAPI->TexCoord2f(0,1);
			gEngfuncs.pTriAPI->Vertex3f(iX,iY+iWidthCheck + 20,0);
			gEngfuncs.pTriAPI->TexCoord2f(1,1);
			gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[m_TextBg_Right].width,iY+iWidthCheck + 20,0);
			gEngfuncs.pTriAPI->TexCoord2f(1,0);
			gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[m_TextBg_Right].width,iY,0);
			gEngfuncs.pTriAPI->TexCoord2f(0,0);
			gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
			gEngfuncs.pTriAPI->End();*/
		}

		if(g_rgDrawFontText[i].iCenter)
		{			
			Fonts_Draw(pText,g_rgDrawFontText[i].x - iLen/2,g_rgDrawFontText[i].y,1000,g_rgDrawFontText[i].iScale);
		}
		else Fonts_Draw(pText,g_rgDrawFontText[i].x,g_rgDrawFontText[i].y,1000,g_rgDrawFontText[i].iScale);
	}
}