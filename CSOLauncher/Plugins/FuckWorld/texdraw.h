void TEXD_BeginDraw(void);
void TEXD_EndDraw(void);
void TEXD_BindTexture(int texid);
void TEXD_SetColor(int r, int g, int b, int a);
void TEXD_SetRenderMode(int mode);
void TEXD_DrawTexture(int x, int y, float w, float h, wrect_t *prc, float size = 1);