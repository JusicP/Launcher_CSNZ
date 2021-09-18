#include "base.h" 
#include "BaseUI.h" 

#define FONTS_MAX_BUFFER	1000
FT_Library  library;
FT_Face     face;
int iError;
int Fonts_iColor_R = 0;
int Fonts_iColor_G = 0;
int Fonts_iColor_B = 0;
int Fonts_iColor_A = 0;
int iWidthCheck = 0;
int iStartFontIndex = 6800;
int Fonts_Count;
int Fonts_Buffer[FONTS_MAX_BUFFER];
struct xCharTexture
{
 GLuint  m_texID;
 wchar_t m_chaID;
 int     m_Width;
 int     m_Height;
 int     m_adv_x;
 int     m_adv_y;
 int     m_delta_x;
 int     m_delta_y;
 public:
 xCharTexture()
 {
  m_texID  = 0;
  m_chaID  = 0;
  m_Width  = 0;
  m_Height = 0;
 }
}Fonts_TexID[FONTS_MAX_BUFFER];

int Fonts_CheckExists(wchar_t ch)
{
	for(int i = 0;i<Fonts_Count;i++)
	{
		if(65536*iWidthCheck + ch == Fonts_Buffer[i])
		{
			return i;
		}
	}
	return -1;
}
int Fonts_LoadChar(wchar_t ch)
{
	int iCallBack = Fonts_CheckExists(ch);
	if(iCallBack>-1) return iCallBack;
	if(FT_Load_Char(face, ch,FT_LOAD_FORCE_AUTOHINT|
	(TRUE ? FT_LOAD_TARGET_NORMAL : FT_LOAD_MONOCHROME | FT_LOAD_TARGET_MONO) )  )
	{
		return 0;
	}
    xCharTexture& charTex = Fonts_TexID[Fonts_Count];
	FT_Glyph glyph;
	if(FT_Get_Glyph( face->glyph, &glyph )) return 0;
	FT_Render_Glyph( face->glyph,   FT_RENDER_MODE_LCD );
	FT_Glyph_To_Bitmap( &glyph, ft_render_mode_normal, 0, 1 );
	FT_BitmapGlyph bitmap_glyph = (FT_BitmapGlyph)glyph;

	FT_Bitmap& bitmap=bitmap_glyph->bitmap;
	int width  =  bitmap.width;
	int height =  bitmap.rows;
	face->size->metrics.y_ppem;
	face->glyph->metrics.horiAdvance;

	charTex.m_Width = width;
	charTex.m_Height = height;
	charTex.m_adv_x = face->glyph->advance.x / 64.0f;
	charTex.m_adv_y = face->size->metrics.y_ppem; 
	charTex.m_delta_x = (float)bitmap_glyph->left;
	charTex.m_delta_y = (float)bitmap_glyph->top - height;
	charTex.m_texID = g_pSurface->CreateNewTextureID();/*iStartFontIndex + Fonts_Count*/;
	Tri_Enable(GL_TEXTURE_2D);
    Tri_BindTexture(GL_TEXTURE_2D,charTex.m_texID);
	char* pBuf = new char[width * height * 4];
	for(int j=0; j  < height ; j++)
	{
		for(int i=0; i < width; i++)
		{
			unsigned char _vl =  (i>=bitmap.width || j>=bitmap.rows) ? 0 : bitmap.buffer[i + bitmap.width*j];
			pBuf[(4*i + (height - j - 1) * width * 4)  ] = 0xFF;
			pBuf[(4*i + (height - j - 1) * width * 4)+1] = 0xFF;
			pBuf[(4*i + (height - j - 1) * width * 4)+2] = 0xFF;
			pBuf[(4*i + (height - j - 1) * width * 4)+3] = _vl;
		}
	}

	Tri_TexImage2D( GL_TEXTURE_2D,0,GL_RGBA,width, height ,0,GL_RGBA,GL_UNSIGNED_BYTE,pBuf);
	Tri_SetTextureParam();
	Tri_TexEnvf(GL_TEXTURE_2D,GL_TEXTURE_ENV_MODE,GL_REPLACE);
	delete[] pBuf;
	LogToFile("已使用字体缓存区:%d/%d[字体ID:%d分配的纹理ID:%d]",Fonts_Count,FONTS_MAX_BUFFER,65536*iWidthCheck + ch,charTex.m_texID);
	Fonts_Buffer[Fonts_Count] = 65536*iWidthCheck + ch;
	Fonts_Count ++ ;
	return (Fonts_Count-1);
}
xCharTexture* Font_GetChar(wchar_t ch)
{
  int iCallBack = Fonts_LoadChar(ch);
  return &Fonts_TexID[iCallBack];
}
int Fonts_GetLen(wchar_t* _strText)
{
	int sx = 0;
	size_t nLen = wcslen(_strText);
 
	for(int i = 0 ; i <(int)nLen ; i ++)
	{
		xCharTexture* pCharTex = Font_GetChar(_strText[i]);
		int w = pCharTex->m_Width;
		int ch_x = sx + pCharTex->m_delta_x;
		sx += pCharTex->m_adv_x;
	}
	return sx;
}
int Fonts_Draw(wchar_t* _strText,int x , int y, int maxW , int h)
{
	int sx = x;
	int sy = y;
	int maxH = h;
	size_t nLen = wcslen(_strText);
 
	for(int i = 0 ; i <(int)nLen ; i ++)
	{
		if(_strText[i] =='\n')
		{
			sx = x ; sy += (iWidthCheck);
			continue;
		}
		xCharTexture* pCharTex = Font_GetChar(_strText[i]);
		Tri_BindTexture(GL_TEXTURE_2D,pCharTex->m_texID);
		Tri_SetTextureParam();
		
		Tri_BlendFunc(GL_SRC_ALPHA,GL_ONE);
		int w = pCharTex->m_Width;
		int h = pCharTex->m_Height;
		int ch_x = sx + pCharTex->m_delta_x;
		int ch_y = sy - h - pCharTex->m_delta_y;
		if(maxH < h) maxH = h;

		if(_strText[i] =='$') 
			ch_y-=2;
		
		Tri_Enable(GL_BLEND);
		Tri_BlendFunc(GL_SRC_ALPHA,GL_ONE_MINUS_SRC_ALPHA);
		if(g_iVideoMode)
		{
			glColor4ub(Fonts_iColor_R,Fonts_iColor_G,Fonts_iColor_B,Fonts_iColor_A);
		}
		else gEngfuncs.pTriAPI->Color4ub(Fonts_iColor_R,Fonts_iColor_G,Fonts_iColor_B,255);

		gEngfuncs.pTriAPI->Begin ( TRI_QUADS );
		{
			gEngfuncs.pTriAPI->TexCoord2f(0.0f, 1.0f); gEngfuncs.pTriAPI->Vertex3f(ch_x      , ch_y    ,  0);
			gEngfuncs.pTriAPI->TexCoord2f(1.0f, 1.0f); gEngfuncs.pTriAPI->Vertex3f(ch_x +  w, ch_y    ,  0);
			gEngfuncs.pTriAPI->TexCoord2f(1.0f, 0.0f); gEngfuncs.pTriAPI->Vertex3f(ch_x +  w, ch_y + h,  0);
			gEngfuncs.pTriAPI->TexCoord2f(0.0f, 0.0f); gEngfuncs.pTriAPI->Vertex3f(ch_x     , ch_y + h, 0);
		}
		gEngfuncs.pTriAPI->End();
		sx += pCharTex->m_adv_x;
		if(sx > x + maxW)
		{
			sx = x ; sy += maxH + 12;
		}
	}
	return sx;
}
int Fonts_Draw2(wchar_t* _strText,int x , int y, int maxW , int h, int iH)
{
	int sx = x;
	int sy = y;
	int maxH = h;
	size_t nLen = wcslen(_strText);

	for(int i = 0 ; i <(int)nLen ; i ++)
	{
		if(_strText[i] =='\n')
		{
			sx = x ; sy += (iWidthCheck + iH);
			continue;
		}
		xCharTexture* pCharTex = Font_GetChar(_strText[i]);
		Tri_BindTexture(GL_TEXTURE_2D,pCharTex->m_texID);
		Tri_SetTextureParam();
		
		Tri_BlendFunc(GL_SRC_ALPHA,GL_ONE); 
		int w = pCharTex->m_Width;
		int h = pCharTex->m_Height;
		int ch_x = sx + pCharTex->m_delta_x;
		int ch_y = sy - h - pCharTex->m_delta_y;
		if(maxH < h) maxH = h;

		// 不知道该怎么办..
		if(_strText[i] =='$') 
			ch_y-=1;
		
		Tri_Enable(GL_BLEND);
		Tri_BlendFunc(GL_SRC_ALPHA,GL_ONE_MINUS_SRC_ALPHA);
		if(g_iVideoMode)
		{
			glColor4ub(Fonts_iColor_R,Fonts_iColor_G,Fonts_iColor_B,Fonts_iColor_A);
		}
		else gEngfuncs.pTriAPI->Color4ub(Fonts_iColor_R,Fonts_iColor_G,Fonts_iColor_B,255);

		gEngfuncs.pTriAPI->Begin ( TRI_QUADS );
		{
			gEngfuncs.pTriAPI->TexCoord2f(0.0f, 1.0f); gEngfuncs.pTriAPI->Vertex3f(ch_x      , ch_y    ,  0);
			gEngfuncs.pTriAPI->TexCoord2f(1.0f, 1.0f); gEngfuncs.pTriAPI->Vertex3f(ch_x +  w, ch_y    ,  0);
			gEngfuncs.pTriAPI->TexCoord2f(1.0f, 0.0f); gEngfuncs.pTriAPI->Vertex3f(ch_x +  w, ch_y + h,  0);
			gEngfuncs.pTriAPI->TexCoord2f(0.0f, 0.0f); gEngfuncs.pTriAPI->Vertex3f(ch_x     , ch_y + h, 0);
		}
		gEngfuncs.pTriAPI->End();
		sx += pCharTex->m_adv_x;
		if(sx > x + maxW)
		{
			sx = x ; sy += maxH + iH;
		}
	}
	return sx;
}
int Fonts_GetHeight(wchar_t* _strText, int maxW ,int iH)
{
	int iHeight = 0;
	int sx = 0;
	size_t nLen = wcslen(_strText);
 
	for(int i = 0 ; i <(int)nLen ; i ++)
	{
		xCharTexture* pCharTex = Font_GetChar(_strText[i]);
		int w = pCharTex->m_Width;
		int ch_x = sx + pCharTex->m_delta_x;
		sx += pCharTex->m_adv_x;

		if(_strText[i] =='\n')
		{
			iHeight += (iWidthCheck + iH);			
		}	
		if(sx > maxW)
		{
			sx = 0 ; iHeight += iWidthCheck + iH;
		}
	}
	return iHeight;
}
void Fonts_SetColor(int r,int g,int b,int a)
{
	Fonts_iColor_R = r;
	Fonts_iColor_G = g;
	Fonts_iColor_B = b;
	Fonts_iColor_A = a;
}
void Fonts_SetSize(int iW,int iH)
{
	FT_Set_Pixel_Sizes(face,iW, iH);
	iWidthCheck = iW;
}

void Fonts_Init(char *FontName,int iW,int iH)
{
	LogToFile("===初始化游戏内字体===");
	iError = FT_Init_FreeType( &library );
	if ( iError )
	{
		LogToFile("初始化失败");
	}
	
	iError = FT_New_Face( library, FontName,0,&face );
	if ( iError == FT_Err_Unknown_File_Format )
	{
		LogToFile("无法识别的字体文件");
	}
	else if ( iError )
	{
		LogToFile("无法使用的字体文件");
	}
	else LogToFile("成功加载字体文件%s",FontName);
	Fonts_Count = 0;
	FT_Select_Charmap(face, FT_ENCODING_UNICODE);

	FT_Set_Pixel_Sizes(face,iW, iH);
	iWidthCheck = iW;
}
void Fonts_C2W(wchar_t *pwstr,size_t len,const char *str)
{
	if(str)
    {
		size_t nu = strlen(str);
		size_t n =(size_t)::MultiByteToWideChar(CP_ACP,0,(const char *)str,(int)nu,NULL,0);
		if(n>=len)n=len-1;
		::MultiByteToWideChar(CP_ACP,0,(const char *)str,(int)nu,pwstr,(int)n);
		pwstr[n]=0;
    }
}
void Fonts_Free(void)
{
	FT_Done_Face(face);
	FT_Done_FreeType(library);
	return;
}

void Fonts_LoadString(wchar_t* _strText)
{
	size_t nLen = wcslen(_strText); 
	for(int i = 0 ; i <(int)nLen ; i ++)
	{
		xCharTexture* pCharTex = Font_GetChar(_strText[i]);
	}

	//LogToFile("LoadText: %s", UnicodeToANSI(_strText));
}