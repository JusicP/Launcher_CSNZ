#include <VGUI\IPanel.h>
#include <VGUI\ISurface.h>
#include <VGUI\ILocalize.h>
#include <VGUI\IScheme.h>
#include <r_studioint.h>
#include <custom.h>
#include <exportfuncs.h>

void BaseUI_InstallHook(void);

extern vgui::ISurface *g_pSurface;
extern vgui::ILocalize *g_pLocalize;
extern IFileSystem *g_pFileSystem;

extern mh_interface_t *g_pInterface;

extern vgui::ISchemeManager *g_SchemeManager;

extern struct model_s *(*g_pfnCL_GetModelByIndex)(int index);
//extern engine_studio_api_t IEngineStudio;

extern hook_t *g_phCL_GetModelByIndex;
extern void (*g_pfnCL_AddToResourceList)(resource_t *pResource, resource_t *pList);
extern hook_t *g_phCL_AddToResourceList;

struct model_s *CL_GetModelByIndex(int index);
void CL_AddToResourceList(resource_t *pResource, resource_t *pList);

#define CL_GETMODELBYINDEX_SIGNAL "\x83\xEC\x10\x56\x57\x8B\x7C\x24\x1C\x8B\x34\xBD\x50\xE9\xF1\x02\x85\xF6"
#define CL_ADDTORESOURCELIST_SIGNAL "\x8B\x44\x24\x04\x8B\x88\x84\x00\x00\x00\x85\xC9"

extern char g_szModelPrecache[512][MAX_QPATH];
extern int g_iModelPrecacheNums;