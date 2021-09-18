#ifndef _TGA
#define _TGA
#define MAX_TGA 700
#define MH_MAX_TGA	750


struct Tga
{
	char szName[256];
	int iTexture;
	int iWidth;
	int iHeight;
	float fScissorRectW;
	float fScissorRectH;
};


extern GLuint TGATexturdID[MAX_TGA+10+30];

extern imagedata_s g_MHTga[MH_MAX_TGA];
extern Tga g_Texture[1024];

struct DrawTgaItem
{
	char szName[64];
	int iFunction;
	int iCenter;
	int r,g,b;
	int x,y,w,h;
	int iMode;
	float flStartDisplayTime;
	float flEndDisplayTime;
	int iChanne;
	int iMessage;
	int iMHTgaID;
	float fScale;
};

struct Vertex_t
{
	Vertex_t(void) {}

	Vertex_t(const Vector2D &pos, const Vector2D &coord = Vector2D(0, 0))
	{
		m_Position = pos;
		m_TexCoord = coord;
	}

	void Init(const Vector2D &pos, const Vector2D &coord = Vector2D(0, 0))
	{
		m_Position = pos;
		m_TexCoord = coord;
	}

	Vector2D m_Position;
	Vector2D m_TexCoord;
};

void DrawTgaAdd(DrawTgaItem rgTga);
void DrawTgaRedraw();
void DrawTgaLoadList(void);
int DrawTgaGetID(char *pszName);
void DrawTgaRedraw(void);
void DrawTargaImageInitialize(void);
int DrawBmpGetID(char *pszName);


void MetaHookLoadTattoo(void);

int MH_DrawTGAFunction(int index,int r,int g,int b,int a,int iX,int iY,float scale);
int MH_DrawTGAFunction2(int index,int iX,int iY,int iW,int iH, int alpha);
int MH_DrawTGAFunction3(int index,int iX,int iY,float fPercent,int iH, int alpha);
int MH_DrawTGA_9(int tid[3][3],int iX,int iY,int iW,int iH, int alpha);
int MH_DrawTGA_3(int tid[3],int iX,int iY,int iW,int iH, int alpha);
int MH_DrawPolygon(int index,int n, Vertex_t *pVertices);
void LoadTga_9(int tid[3][3],char *szName);
void LoadTga_3(int tid[3],char *szName);

extern int g_UI_Panel[3][3];
extern int g_UI_Panel_Dark[3][3];
//extern int g_UI_OutPut[3][3];
//extern int g_UI_Button[3][3];

int FindTexture(char *pszName);

byte *MetaHookRebuildTexture(const byte *source, int inWidth, int inHeight, int outWidth, int outHeight);
#endif