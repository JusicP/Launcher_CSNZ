#include <winsani_in.h>
#include <windows.h>
#include <winsani_out.h>
#include <stdio.h>
#include <malloc.h>
#include <interface.h>
#include <metahook.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

//typedef vec_t vec3_t[3];

typedef float vec_t;
typedef float vec2_t[2];
typedef float vec3_t[3];

#include <math.h>
#include <vector.h>
#include <wrect.h>

typedef int (*pfnUserMsgHook)(const char *pszName, int iSize, void *pbuf);

#define HSPRITE int
//#include <cdll_export.h>
//#include <metahook_api.h>
//#include <plugin_interface.h>
#include <gl/gl.h>
#include <const.h>
#include "pm_defs.h"
#include "HLSDK\engine\cdll_int.h"
#include <triangleapi.h>
#include <cl_entity.h>
#include <event_api.h>
#include <ref_params.h>
#include <com_model.h>
#include <cvardef.h>
#include <studio.h>
#include <r_studioint.h>
#include <pm_movevars.h>
#include <studio.h>

#include "calcscreen.h"
#include "util.h"
#include "exportfuncs.h"
#include "engfuncs.h"
#include "TriAPI.h"
#include "r_efx.h"
#include "overview.h"
#include "client.h"
#include "engfunchook.h"
#include "deathmsg.h"
#include "imagelib.h"
#include "display.h"
#include "message.h"
#include "menu.h"
#include "weapons.h"
#include "parsemsg.h"
#include "drawtargaimage.h"
#include "Fonts.h"
#include "FontText.h"
#include "DrawTABPanel.h"
#include "DeathRun.h"
#include "extraammo.h"
#include "scoreboard.h"
#include "gdboard.h"
#include "drawimage.h" 
#include "playbink.h"
#include "Quest.h"
#include "respawnbar.h"
#include "followicon.h"
#include "zombieescape.h"
#include "zb3ui.h"
#include "zb4ui.h"
#include "mgui.h"
#include "BTEPanel.h"
#include "zbsboard.h"
#include "texdraw.h"
#include "DrawRetina.h"


#define HIDEWEAPON_WEAPON		(1<<0)
#define HIDEWEAPON_FLASHLIGHT	(1<<1)
#define HIDEWEAPON_ALL			(1<<2)
#define HIDEWEAPON_HEALTH		(1<<3)
#define HIDEWEAPON_TIME			(1<<4)
#define HIDEWEAPON_MONEY		(1<<5)
#define HIDEWEAPON_CROSSHAIR	(1<<6)

#define MOD_NONE	1
#define MOD_TDM		2
#define MOD_ZB		3
#define MOD_ZBS		4
#define MOD_ZBU		5
#define MOD_HMS		6
#define MOD_GHOST	7
#define MOD_GD	8
#define MOD_DR	9
#define MOD_ZE		10
#define MOD_ZB3	11
#define MOD_BC 12
#define MOD_FUNMODE 13
#define MOD_HD 14
#define MOD_SD 15
#define MOD_ZB4 16
#define MOD_DM		17

#define MUZZLEFLASH_NORMAL	1
#define MUZZLEFLASH_PPQQ	2
#define MUZZLEFLASH_GUITAR	3


#define EXTRAAMMO_SVDEX	1
#define EXTRAAMMO_MUSKET	2


#define EVENT_DR_START		2
#define EVENT_DR_END		3
#define EVENT_DR_RESET		4
#define EVENT_BALROG		5
#define EVENT_SFMG			6
#define EVENT_SFMG2			7
#define EVENT_INF			8
#define EVENT_INF2			9
#define EVENT_BL3			10
#define EVENT_BL32			11
#define EVENT_M16           12
#define EVENT_M162			13

#define SCOREATTRIB_NONE    0
#define SCOREATTRIB_DEAD    ( 1 << 0 )
#define SCOREATTRIB_BOMB    ( 1 << 1 )
#define SCOREATTRIB_VIP  ( 1 << 2 )
#define SCOREATTRIB_HERO	(1<<3)

#define ZB3DATA_HM_MORALE	1
#define ZB3DATA_ZB_LEVEL	2
#define ZB3DATA_ZB_RAGE		3
#define ZB3DATA_HM_MORALE_MAX	4
#define ZB3DATA_PASS	5
#define ZB3DATA_RETINA	6
#define ZB3DATA_RETINASTOP	7
#define ZB3DATA_CLEARUI	8
#define ZB3DATA_TOPUI	9
#define ZB3DATA_BECOME_ZB	10
#define ZB3DATA_BECOME_HM	11
#define ZB3DATA_USESKILL	12
