#include "base.h"
#include "BaseUI.h"
#include <math.h>       /* log2 */
DrawTgaItem g_Tga[MAX_TGA];
imagedata_s g_MHTga[MH_MAX_TGA];

Tga g_Texture[1024];


int iTotal = 6501;
int iTgaIndex = 1;

void DrawTargaImageInitialize(void)
{
	memset(g_Tga, 0, sizeof(g_Tga));
}
int DrawTgaGetID(char *pszName)
{
	char TgaName[512];	

	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;

	char TgaNameLang[512];
	sprintf(TgaNameLang,"metahook\\tga\\%s_%s.tga",pszName,g_szLanguage);

	hFind = FindFirstFile(TgaNameLang, &FindFileData);	

	if (hFind == INVALID_HANDLE_VALUE)
	{
		sprintf(TgaName,"metahook\\tga\\%s.tga",pszName);
	}
	else 
	{
		sprintf(TgaName,"metahook\\tga\\%s_%s.tga",pszName,g_szLanguage);
	}



	for(int i=0;i<MH_MAX_TGA;i++)
	{
		if(!strcmp(TgaName,g_MHTga[i].name))
		{
			return i;
		}
	}
	// Load IT!
	iTotal = g_pSurface->CreateNewTextureID();
	if(Image_LoadImage(TgaName,&g_MHTga[iTgaIndex],&iTotal))
	{
		sprintf(g_MHTga[iTgaIndex].name,"%s",TgaName);
		//LogToFile(g_MHTga[iTgaIndex].name);
		//iTotal ++;
		iTgaIndex++;
		return (iTgaIndex-1);
	}
	return 0;
}
int DrawBmpGetID(char *pszName)
{
	char TgaName[256];	
	sprintf(TgaName,"cstrike\\%s",pszName);
	for(int i=0;i<MH_MAX_TGA;i++)
	{
		if(!strcmp(TgaName,g_MHTga[i].name))
		{
			return i;
		}
	}
	iTotal = g_pSurface->CreateNewTextureID();
	if(Image_LoadImage(TgaName,&g_MHTga[iTgaIndex],&iTotal))
	{
		sprintf(g_MHTga[iTgaIndex].name,"%s",TgaName);
		//LogToFile(g_MHTga[iTgaIndex].name);
		//iTotal ++;
		iTgaIndex++;
		return (iTgaIndex-1);
	}
	return 0;
}
void DrawTgaLoadList(void)
{
	LogToFile( "===准备加载TGA文件列表===");
	
	FILE* pTgaList;
	static char szBuff[512];
	szBuff[0] = '\0';
	pTgaList = fopen("metahook\\tga\\TgaFilesList.txt", "rt");
	if(pTgaList == NULL)									
	{
		LogToFile( "列表打开失败");
		return;
	}
	while(!feof(pTgaList))
	{
		fgets(szBuff,sizeof(szBuff)-1,pTgaList);
		if(szBuff[strlen(szBuff)-1] =='\n') szBuff[strlen(szBuff)-1] = '\0';

		if(szBuff[0]=='/' && szBuff[1]=='/' || !szBuff[0]) continue;
		iTotal = g_pSurface->CreateNewTextureID();
		if(Image_LoadImage(szBuff,&g_MHTga[iTgaIndex],&iTotal))
		{
			sprintf(g_MHTga[iTgaIndex].name,"%s",szBuff);
			LogToFile(szBuff);
			//iTotal ++;
			iTgaIndex++;
		}
	}


	DeathRunInit();
	MetaHookGDBoardInit();
	g_iRSBgIndex = FindTexture("resource\\hud\\other\\respawn_bg");
	g_iCountBg = FindTexture("resource\\hud\\other\\countbg");

	g_Tga_BombA = FindTexture("resource\\hud\\icon\\bombtargetA");
	g_Tga_BombB = FindTexture("resource\\hud\\icon\\bombtargetB");

	g_ze_hm = FindTexture("resource\\hud\\zombieescape\\ze_hm");
	g_ze_zb = FindTexture("resource\\hud\\zombieescape\\ze_zb");
	g_ze_flag = FindTexture("resource\\hud\\zombieescape\\ze_flag");
	g_ze_me = FindTexture("resource\\hud\\zombieescape\\ze_self");
	g_ze_bar = FindTexture("resource\\hud\\zombieescape\\ze_bar");

	g_tga_Scope = DrawTgaGetID("other\\scope_square");
	g_tga_Scope_Target = DrawTgaGetID("other\\sfscopetarget");
	g_tga_custom_scope_m200 = DrawTgaGetID("other\\scope_m200");
	g_tga_custom_scope = DrawTgaGetID("other\\scope");

	LogToFile( "共有%d个TGA/BMP纹理被成功加载",iTgaIndex);

	// 初始化所有纹理
	
	

}

void DrawTgaAdd(DrawTgaItem rgTempDrawImage)
{
	if(rgTempDrawImage.fScale==0.0) rgTempDrawImage.fScale = 1.0;
	rgTempDrawImage.iMHTgaID = DrawTgaGetID(rgTempDrawImage.szName);
	if (rgTempDrawImage.iChanne <= 0 || rgTempDrawImage.iChanne >= MAX_TGA)
	{
		for (int i = 0; i < MAX_TGA; i++)
		{
			if (!g_Tga[i].flEndDisplayTime)
			{
				g_Tga[i] = rgTempDrawImage;
				break;
			}
		}
	}
	else
	{
		g_Tga[rgTempDrawImage.iChanne] = rgTempDrawImage;
	}
}
void DrawTgaRedraw(void)
{		 
	for (int i = 0; i < MAX_TGA; i++)
	{
		if (g_MHTga[g_Tga[i].iMHTgaID].texid==-1)
			continue;

		if (!g_Tga[i].flEndDisplayTime)
			continue;

		if (g_flTime > g_Tga[i].flEndDisplayTime)
		{
			g_Tga[i].flEndDisplayTime = 0.0;
			continue;
		}

		int r, g, b;
		r = g_Tga[i].r;
		g = g_Tga[i].g;
		b = g_Tga[i].b;
		float fA;

		switch (g_Tga[i].iMode)
		{
			case 1:
			{
				float flHasDisplayTime = g_flTime - g_Tga[i].flStartDisplayTime;
				float flNeedDisplayTime = g_Tga[i].flEndDisplayTime - g_Tga[i].flStartDisplayTime;
				fA = flHasDisplayTime / flNeedDisplayTime;
				break;
			}
			case 2:
			{
				float flHasDisplayTime = g_flTime - g_Tga[i].flStartDisplayTime;
				float flNeedDisplayTime = g_Tga[i].flEndDisplayTime - g_Tga[i].flStartDisplayTime;
				fA = 1.0 - (flHasDisplayTime / flNeedDisplayTime);
				break;
			}
			case 3:
			{
				float flHasDisplayTime = g_flTime - g_Tga[i].flStartDisplayTime;
				float flNeedDisplayTime = g_Tga[i].flEndDisplayTime - g_Tga[i].flStartDisplayTime;
				fA = (flHasDisplayTime / flNeedDisplayTime * 2.0);
				if (fA > 1.0)
					fA = 2.0-fA;
				break;
			}
			default: 
			{
				fA = 1.0;
				break;
			}
		}
		//
		
		static int iX,iY,width,height;
		if(g_Tga[i].w>0 && g_Tga[i].h>0)
		{
			width = g_Tga[i].w;
			height = g_Tga[i].h;
		}
		else
		{
			width = g_MHTga[g_Tga[i].iMHTgaID].width * g_Tga[i].fScale ;
			height = g_MHTga[g_Tga[i].iMHTgaID].height * g_Tga[i].fScale ;
		}

		if (g_Tga[i].iCenter)
		{
			iX = g_Tga[i].x - width/2;
			iY = g_Tga[i].y - height/2;
		}
		else
		{
			iX = g_Tga[i].x;
			iY = g_Tga[i].y;
		}

		Tri_Enable(GL_TEXTURE_2D);
		Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_Tga[i].iMHTgaID].texid);
		if(g_iVideoMode)
		{
			glColor4ub(r,g,b,fA*255);
		}
		else gEngfuncs.pTriAPI->Color4ub(r,g,b,255*fA);
		Tri_Enable(GL_BLEND);
		Tri_Enable(GL_ALPHA_TEST);
		Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
		Tri_AlphaFunc(GL_GREATER, 0.0);
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
		gEngfuncs.pTriAPI->TexCoord2f(0,1);
		gEngfuncs.pTriAPI->Vertex3f(iX,iY+height,0);

		gEngfuncs.pTriAPI->TexCoord2f(1,1);
		gEngfuncs.pTriAPI->Vertex3f(iX+width,iY+height,0);
		
		gEngfuncs.pTriAPI->TexCoord2f(1,0);
		gEngfuncs.pTriAPI->Vertex3f(iX+width,iY,0);
		
		gEngfuncs.pTriAPI->TexCoord2f(0,0);
		gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
		gEngfuncs.pTriAPI->End();
	}
}
int MH_DrawPolygon(int index,int n, Vertex_t *pVertices)
{
	g_pSurface->DrawSetTexture(g_Texture[index].iTexture);
	g_pSurface->DrawSetColor(255,255,255,255);

	glEnable(GL_TEXTURE_2D);
	glBegin(GL_POLYGON);

	for (int i = 0; i < n; i++)
	{
		glTexCoord2f(pVertices[i].m_TexCoord.x, pVertices[i].m_TexCoord.y);
		glVertex2f(pVertices[i].m_Position.x, pVertices[i].m_Position.y);
	}
	glEnd();
	return 1;
}
int MH_DrawTGAFunction(int index,int r,int g,int b,int a,int iX,int iY,float scale)
{
	if (!index) return 0;
	/*Tri_Enable(GL_TEXTURE_2D);
	Tri_Enable(GL_BLEND);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	

	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[index].texid);
	if(g_iVideoMode)
	{
		glColor4ub(r,g,b,a);
	}
	else gEngfuncs.pTriAPI->Color4ub(r,g,b,a);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
	
		
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[index].height*scale,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[index].width*scale,iY+g_MHTga[index].height*scale,0);
		
	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[index].width*scale,iY,0);
		
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
	gEngfuncs.pTriAPI->End();*/
	g_pSurface->DrawSetTexture(index);
	g_pSurface->DrawSetColor(r,g,b,a);
	int w,h;
	g_pSurface->DrawGetTextureSize(index,w,h);
	Tri_Enable(GL_BLEND);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	g_pSurface->DrawTexturedRect(iX,iY,iX+w * scale,iY+h * scale);	



	return 1;
}
int MH_DrawTGAFunction2(int index,int iX,int iY,int iW,int iH, int alpha)
{
	if (!index) return 0;
	/*if(!index) return 0;

	Tri_Enable(GL_TEXTURE_2D);
	Tri_Enable(GL_BLEND);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	

	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[index].texid);
	if(g_iVideoMode)
	{
		glColor4ub(255,255,255,alpha);
	}
	else gEngfuncs.pTriAPI->Color4ub(255,255,255,alpha);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
	
		
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY+iH,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iX+iW,iY+iH,0);
		
	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iX+iW,iY,0);
		
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
	gEngfuncs.pTriAPI->End();*/

	g_pSurface->DrawSetTexture(index);
	g_pSurface->DrawSetColor(255,255,255,alpha);
	/*int w,h;
	g_pSurface->DrawGetTextureSize(g_iTextTexture,w,h);*/
	Tri_Enable(GL_BLEND);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	g_pSurface->DrawTexturedRect(iX,iY,iX+iW,iY+iH);

	return 1;
}
int MH_DrawTGAFunction3(int index,int iX,int iY,float fPercent,int iH, int alpha)
{
	if (!index) return 0;
	int iW = g_Texture[index].iWidth;
	

	g_pSurface->DrawSetTexture(g_Texture[index].iTexture);
	g_pSurface->DrawSetColor(255,255,255,alpha);

	Tri_Enable(GL_TEXTURE_2D);
	glBegin(GL_QUADS);
	glTexCoord2f(0, 0);
	glVertex2f(iX, iY);

	glTexCoord2f(g_Texture[index].fScissorRectW *fPercent, 0);
	glVertex2f(iX+fPercent*iW, iY);
	glTexCoord2f(g_Texture[index].fScissorRectW*fPercent, g_Texture[index].fScissorRectH);
	glVertex2f(iX+fPercent*iW, iY + iH);
	glTexCoord2f(0, g_Texture[index].fScissorRectH);
	glVertex2f(iX, iY+iH);


	glEnd();

	return 1;
}

int MH_DrawTGA_9(int tid[3][3],int iX,int iY,int iW,int iH, int alpha)
{
	if (!tid[0][0]) return 0;
	
	int length, width, width2, height, height2;
	g_pSurface->DrawGetTextureSize(tid[0][0],width,height);
	g_pSurface->DrawGetTextureSize(tid[0][2],width2,height2);
	length = iW - width - width2;

	MH_DrawTGAFunction2(tid[0][0], iX, iY, width, height, alpha);	
	MH_DrawTGAFunction2(tid[0][1], iX + width, iY, length, height, alpha);
	MH_DrawTGAFunction2(tid[0][2], iX + length + width, iY, width, height, alpha);

	iY += height;
	g_pSurface->DrawGetTextureSize(tid[0][0],width2,height2);
	g_pSurface->DrawGetTextureSize(tid[2][0],width,height);
	height = iH - height - height2;
	//width = g_MHTga[tid[1][0]].width;	
	g_pSurface->DrawGetTextureSize(tid[1][0],width2,height2);
	g_pSurface->DrawGetTextureSize(tid[1][2],width,height2);
	length = iW - width2 - width;

	MH_DrawTGAFunction2(tid[1][0], iX, iY, width, height, alpha);
	MH_DrawTGAFunction2(tid[1][1], iX + width, iY, length, height, alpha);
	MH_DrawTGAFunction2(tid[1][2], iX + length + width, iY, width, height, alpha);

	iY += height;
	g_pSurface->DrawGetTextureSize(tid[2][0],width,height);
	g_pSurface->DrawGetTextureSize(tid[2][2],width2,height2);
	length = iW - width - width2;

	MH_DrawTGAFunction2(tid[2][0], iX, iY, width, height, alpha);	
	MH_DrawTGAFunction2(tid[2][1], iX + width, iY, length, height, alpha);
	MH_DrawTGAFunction2(tid[2][2], iX + length + width, iY, width, height, alpha);

	return 1;
}

int MH_DrawTGA_3(int tid[3],int iX,int iY,int iW,int iH, int alpha)
{
	if (!tid[0]) return 0;
	
	int length, height, width[2];
	g_pSurface->DrawGetTextureSize(tid[0],width[0],height);
	g_pSurface->DrawGetTextureSize(tid[2],width[1],height);
	height = iH;
	length = iW - width[0] - width[1];

	MH_DrawTGAFunction2(tid[0], iX, iY, width[0], height, alpha);	
	MH_DrawTGAFunction2(tid[1], iX + width[0], iY, length, height, alpha);
	MH_DrawTGAFunction2(tid[2], iX + length + width[0], iY, width[1], height, alpha);


	return 1;
}
void LoadTga_9(int tid[3][3],char *szName)
{
	char str[3][10]={"top","center","bottom"};
	char str2[3][10]={"left","center","right"};

	for (int i = 0;i <= 2; i++)
	{
		for (int j = 0;j <= 2; j++)
		{
			char name[64];
			sprintf(name,"gfx\\ui\\%s\\%s_%s",szName,str[i],str2[j]);
			tid[i][j] = g_pSurface->CreateNewTextureID();
			g_pSurface->DrawSetTextureFile(tid[i][j],name,true,true);
		}
	}

}
void LoadTga_3(int tid[3],char *szName)
{
	char str[3][10]={"left","center","right"};

	for (int i = 0;i <= 2; i++)
	{
		char name[64];
		sprintf(name,"gfx\\ui\\%s\\%s",szName,str[i]);
		tid[i] = g_pSurface->CreateNewTextureID();
		g_pSurface->DrawSetTextureFile(tid[i],name,true,true);
	}
}


/*int FindTexture(char *pszName)
{
	for(int i=0;i<iTotalTexture;i++)
	{
		if(!strcmp(pszName,g_Texture[i].szName))
		{
			return i;
		}
	}
	
	g_Texture[iTotalTexture].iTexture = g_pSurface->CreateNewTextureID();
	g_pSurface->DrawSetTextureFile(g_Texture[iTotalTexture].iTexture,pszName,true,true);
	strcpy(g_Texture[iTotalTexture].szName,pszName);

	g_pSurface->DrawGetTextureSize(g_Texture[iTotalTexture].iTexture,g_Texture[iTotalTexture].iWidth,g_Texture[iTotalTexture].iHeight);
	
	iTotalTexture++;

	return iTotalTexture - 1;
}*/
int iTotalTexture = 0;
unsigned int log2( unsigned int x )
{
  unsigned int ans = 0 ;
  while( x>>=1 ) ans++;
  return ans+1 ;
}
bool IsPowerOfTwo(ulong x)
{
    return (x & (x - 1)) == 0;
}

int FindTexture(char *pszName)
{
	for(int i=0;i<iTotalTexture;i++)
	{
		if(!strcmp(pszName,g_Texture[i].szName))
		{
			return i;
		}
	}
	
	g_Texture[iTotalTexture].iTexture = g_pSurface->CreateNewTextureID();
	g_pSurface->DrawSetTextureFile(g_Texture[iTotalTexture].iTexture,pszName,true,true);
	strcpy(g_Texture[iTotalTexture].szName,pszName);

	g_pSurface->DrawGetTextureSize(g_Texture[iTotalTexture].iTexture,g_Texture[iTotalTexture].iWidth,g_Texture[iTotalTexture].iHeight);


	if(g_Texture[iTotalTexture].iWidth)
	{
		if(IsPowerOfTwo(g_Texture[iTotalTexture].iWidth)) g_Texture[iTotalTexture].fScissorRectW = 1.0;
		else
		{
			int iScaleW=log2(g_Texture[iTotalTexture].iWidth);

			double fScaleW = pow(2.0,double(iScaleW));
			g_Texture[iTotalTexture].fScissorRectW = float(g_Texture[iTotalTexture].iWidth)/fScaleW;
		}
	}
	if(g_Texture[iTotalTexture].iHeight)
	{
		if(IsPowerOfTwo(g_Texture[iTotalTexture].iHeight)) g_Texture[iTotalTexture].fScissorRectH = 1.0;
		else
		{
			int iScaleH=log2(g_Texture[iTotalTexture].iHeight);

			double fScaleH = pow(2.0,double(iScaleH));
			g_Texture[iTotalTexture].fScissorRectH = float(g_Texture[iTotalTexture].iHeight)/iScaleH;
		}
	}
	iTotalTexture++;

	return iTotalTexture - 1;
}
