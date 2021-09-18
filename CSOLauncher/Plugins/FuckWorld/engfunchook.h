#ifndef ENGFUNC_HOOK
#define ENGFUNC_HOOK

struct model_s *Engfunc_LoadMapSprite(const char *pszPath);
byte *Engfunc_COM_LoadFile(char *pszPath, int iUseHunk, int *piLength);
char *Engfunc_COM_ParseFile(char *pszData, char *pszToken);
void Engfunc_COM_FreeFile(void *pBuffer);
int EngFunc_AddCommand(char *szCmds, void (*pFunction)(void));
HSPRITE	Engfunc_SPR_Load(const char *pszSprite );
void Engfunc_BloodSprite( float * org, int colorindex, int modelIndex, int modelIndex2, float size );
void Engfunc_BloodStream( float * org, float * dir, int pcolor, int speed );
void Engfunc_PlaySound( int ent, float *origin, int channel, const char *sample, float volume, float attenuation, int fFlags, int pitch );
void Engfunc_WeaponAnim( int sequence, int body );
void EngFunc_SPR_DrawAdditive(int frame, int x, int y, const wrect_t *prc);
int	Engfunc_ClientCmd( char *szCmdString );
#endif 