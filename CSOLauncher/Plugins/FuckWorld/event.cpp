#include "base.h"
#include "event.h"
#include "msghook.h"

void EV_FireUSP(struct event_args_s *args);
void EV_FireMP5N(struct event_args_s *args);
void EV_FireAK47(struct event_args_s *args);
void EV_FireAug(struct event_args_s *args);
void EV_FireDeagle(struct event_args_s *args);
void EV_FireG3SG1(struct event_args_s *args);
void EV_FireSG550(struct event_args_s *args);
void EV_FireGlock18(struct event_args_s *args);
void EV_FireM249(struct event_args_s *args);
void EV_FireM3(struct event_args_s *args);
void EV_FireM4A1(struct event_args_s *args);
void EV_FireMac10(struct event_args_s *args);
void EV_FireP90(struct event_args_s *args);
void EV_FireP228(struct event_args_s *args);
void EV_FireAWP(struct event_args_s *args);
void EV_FireScout(struct event_args_s *args);
void EV_FireSG552(struct event_args_s *args);
void EV_FireTMP(struct event_args_s *args);
void EV_FireFiveSeven(struct event_args_s *args);
void EV_FireUMP45(struct event_args_s *args);
void EV_FireXM1014(struct event_args_s *args);
void EV_FireEliteLeft(struct event_args_s *args);
void EV_FireEliteRight(struct event_args_s *args);
void EV_Knife(struct event_args_s *args);
void EV_FireGalil(struct event_args_s *args);
void EV_FireFamas(struct event_args_s *args);
void EV_FireSprifle(struct event_args_s *args);
void EV_FireM1887XMAS(struct event_args_s *args);
void EV_FireSkull4Left(struct event_args_s *args);
void EV_FireSkull4Right(struct event_args_s *args);
void EV_FireDMP7A1Left(struct event_args_s *args);
void EV_FireDMP7A1Right(struct event_args_s *args);
void EV_FireSkull3Left(struct event_args_s *args);
void EV_FireSkull3Right(struct event_args_s *args);

int g_iShotsFired;
int g_iAnim = 0;

void Event_Init(void)
{
	gEngfuncs.pfnHookEvent("events/usp.sc", EV_FireUSP);
	gEngfuncs.pfnHookEvent("events/mp5n.sc", EV_FireMP5N);
	gEngfuncs.pfnHookEvent("events/ak47.sc", EV_FireAK47);
	gEngfuncs.pfnHookEvent("events/aug.sc", EV_FireAug);
	gEngfuncs.pfnHookEvent("events/deagle.sc", EV_FireDeagle);
	gEngfuncs.pfnHookEvent("events/g3sg1.sc", EV_FireG3SG1);
	gEngfuncs.pfnHookEvent("events/sg550.sc", EV_FireSG550);
	gEngfuncs.pfnHookEvent("events/glock18.sc", EV_FireGlock18);
	gEngfuncs.pfnHookEvent("events/m249.sc", EV_FireM249);
	gEngfuncs.pfnHookEvent("events/m3.sc", EV_FireM3);
	gEngfuncs.pfnHookEvent("events/m4a1.sc", EV_FireM4A1);
	gEngfuncs.pfnHookEvent("events/mac10.sc", EV_FireMac10);
	gEngfuncs.pfnHookEvent("events/p90.sc", EV_FireP90);
	gEngfuncs.pfnHookEvent("events/p228.sc", EV_FireP228);
	gEngfuncs.pfnHookEvent("events/awp.sc", EV_FireAWP);
	gEngfuncs.pfnHookEvent("events/scout.sc", EV_FireScout);
	gEngfuncs.pfnHookEvent("events/sg552.sc", EV_FireSG552);
	gEngfuncs.pfnHookEvent("events/tmp.sc", EV_FireTMP);
	gEngfuncs.pfnHookEvent("events/fiveseven.sc", EV_FireFiveSeven);
	gEngfuncs.pfnHookEvent("events/ump45.sc", EV_FireUMP45);
	gEngfuncs.pfnHookEvent("events/xm1014.sc", EV_FireXM1014);
	gEngfuncs.pfnHookEvent("events/elite_left.sc", EV_FireEliteLeft);
	gEngfuncs.pfnHookEvent("events/elite_right.sc", EV_FireEliteRight);
	gEngfuncs.pfnHookEvent("events/knife.sc", EV_Knife);
	gEngfuncs.pfnHookEvent("events/galil.sc", EV_FireGalil);
	gEngfuncs.pfnHookEvent("events/famas.sc", EV_FireFamas);

	gEngfuncs.pfnHookEvent("events/sprifle.sc", EV_FireSprifle);
	gEngfuncs.pfnHookEvent("events/m1887xmas.sc", EV_FireM1887XMAS);
	gEngfuncs.pfnHookEvent("events/skull4_left.sc", EV_FireSkull4Left);
	gEngfuncs.pfnHookEvent("events/skull4_right.sc", EV_FireSkull4Right);
	gEngfuncs.pfnHookEvent("events/dmp7a1_left.sc", EV_FireDMP7A1Left);
	gEngfuncs.pfnHookEvent("events/dmp7a1_right.sc", EV_FireDMP7A1Right);
	gEngfuncs.pfnHookEvent("events/skull3_left.sc", EV_FireSkull3Left);
	gEngfuncs.pfnHookEvent("events/skull3_right.sc", EV_FireSkull3Right);
}

enum event_effect
{
	EVENT_NONE,
	EVENT_PLAYSOUND,
	EVENT_KNIFE,
	EVENT_BALROG_EXPLOSION,
	EVENT_SPEARGUN
};


void (*g_pfnEV_HLDM_FireBullets)(int idx, float *forward, float *right, float *up, int cShots, float *vecSrc, float *vecDirShooting, float *vecSpread, float flDistance, int iBulletType, int iTracerFreq, int *tracerCount, int iPenetration) = (void (*)(int, float *, float *, float *, int, float *, float *, float *, float, int, int, int *, int))0x1902460;
void (*g_pfnEV_EjectBrass)(float *origin, float *velocity, float rotation, int model, int soundtype, int idx, int angle_velocity) = (void (*)(float *, float *, float, int, int, int, int))0x1945180;
void (*g_pfnEV_GetDefaultShellInfo)(event_args_t *args, float *origin, float *velocity, float *ShellVelocity, float *ShellOrigin, float *forward, float *right, float *up, float forwardScale, float upScale, float rightScale, bool bReverseDirection) = (void (*)(event_args_t *, float *, float *, float *, float *, float *, float *, float *, float, float, float, bool))0x1945260;
void (*g_pfnEV_HLDM_CreateSmoke)(float *origin, float *dir, int speed, float scale, int r, int g, int b, int iSmokeType, float *base_velocity, bool bWind, int framerate) = (void (*)(float *, float *, int, float, int, int, int, int, float *, bool, int))0x19017D0;

void EV_HLDM_CreateSmoke(float *origin, float *dir, int speed, float scale, int r, int g, int b, int iSmokeType, float *base_velocity, bool bWind, int framerate)
{
	if(!cl_gunsmoke->value)
		return;

	if(fCurrentFOV > 55.0)
		g_pfnEV_HLDM_CreateSmoke(origin, dir, speed, scale, r, g, b, iSmokeType, base_velocity, bWind, framerate);
}
void EV_GetDefaultShellInfo(event_args_t *args, float *origin, float *velocity, float *ShellVelocity, float *ShellOrigin, float *forward, float *right, float *up, float forwardScale, float upScale, float rightScale, bool bReverseDirection)
{
	g_pfnEV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, forwardScale, upScale, rightScale, bReverseDirection);
}
void EV_EjectBrass(float *origin, float *velocity, float rotation, int model, int soundtype, int idx, int angle_velocity)
{
	g_pfnEV_EjectBrass(origin, velocity, rotation, model, soundtype, idx, angle_velocity);
}
void EV_HLDM_FireBullets(int idx, float *forward, float *right, float *up, int cShots, float *vecSrc, float *vecDirShooting, float *vecSpread, float flDistance, int iBulletType, int iTracerFreq, int *tracerCount, int iPenetration)
{
	g_pfnEV_HLDM_FireBullets(idx, forward, right, up, cShots, vecSrc, vecDirShooting, vecSpread, flDistance, iBulletType, iTracerFreq, tracerCount, iPenetration);
}
void EV_MuzzleFlash(void)
{
	cl_entity_t *ent = GetViewEntity();

	if (!ent)
		return;

	ent->curstate.effects |= EF_MUZZLEFLASH;
}
qboolean EV_IsPlayer(int idx)
{
	if (idx >= 1 && idx <= gEngfuncs.GetMaxClients())
		return true;

	return false;
}
qboolean EV_IsLocal(int idx)
{
	if (IS_FIRSTPERSON_SPEC)
		return (g_iUser2 == idx);
	else
		return gEngfuncs.pEventAPI->EV_IsLocal(idx - 1) ? true : false;
}
void EV_GetGunPosition(event_args_t *args, float *pos, float *origin)
{
	int idx;
	vec3_t view_ofs;

	idx = args->entindex;

	VectorClear(view_ofs);
	view_ofs[2] = 28;

	if (EV_IsPlayer(idx))
	{
		if (EV_IsLocal(idx) && !IS_FIRSTPERSON_SPEC)
			gEngfuncs.pEventAPI->EV_LocalPlayerViewheight(view_ofs);
		else if (args->ducking == 1)
			view_ofs[2] = 12;
	}

	VectorAdd(origin, view_ofs, pos);
}
void VectorScale (const vec3_t in, vec_t scale, vec3_t out)
{
	out[0] = in[0]*scale;
	out[1] = in[1]*scale;
	out[2] = in[2]*scale;
}
void EV_CustomEffect(struct event_args_s *args, int effect)
{	
	if(effect & (1<<EFFECT_SHAKE))
	{
		MSG_BeginWrite("ScreenShake");
		MSG_WriteShort((1<<12)*4);
		MSG_WriteShort((1<<12));
		MSG_WriteShort((1<<12)*4);
		MSG_EndWrite();
	}


	if(effect & (1<<EFFECT_TRACER_ETHEREAL))
	{		
		//gEngfuncs.pEfxAPI->R_UserTracerParticle(
	}
}

enum usp_e
{
	USP_IDLE,
	USP_SHOOT1,
	USP_SHOOT2,
	USP_SHOOT3,
	USP_SHOOT_EMPTY,
	USP_RELOAD,
	USP_DRAW,
	USP_ATTACH_SILENCER,
	USP_UNSIL_IDLE,
	USP_UNSIL_SHOOT1,
	USP_UNSIL_SHOOT2,
	USP_UNSIL_SHOOT3,
	USP_UNSIL_SHOOT_EMPTY,
	USP_UNSIL_RELOAD,
	USP_UNSIL_DRAW,
	USP_DETACH_SILENCER
};

void EV_FireUSP(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	int empty;
	int silencer_on;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	vec3_t smoke_origin;
	float base_scale;
	int weaponid;

	ent = GetViewEntity();
	idx = args->entindex;
	empty = args->bparam1 != false;
	silencer_on = args->bparam2;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][2];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if(g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/pshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);

		if (silencer_on)
		{
			if (!empty)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(USP_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(USP_SHOOT_EMPTY, 2);
		}
		else
		{
			EV_MuzzleFlash();

			if (!empty)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(USP_UNSIL_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(USP_UNSIL_SHOOT_EMPTY, 2);
		}

		VectorCopy(ent->attachment[0], smoke_origin);

		smoke_origin[0] -= forward[0] * 3;
		smoke_origin[1] -= forward[1] * 3;
		smoke_origin[2] -= forward[2] * 3;

		base_scale = gEngfuncs.pfnRandomFloat(0.1, 0.25);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 0, smoke_origin[2], 7, 7, 7, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 20, base_scale + 0.1, 10, 10, 10, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 40, base_scale, 13, 13, 13, 2, velocity, false, 35);
		
	}

	if (EV_IsLocal(idx))
	{
		if (lefthand == 0)
			EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 36.0, -14.0, -14.0, false);
		else
			EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 36.0, -14.0, 14.0, false);

		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 0.5, ShellVelocity);
		ShellVelocity[2] += 45.0;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, 4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 5);

	if (silencer_on)
	{
		if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
			gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
		else
			gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, g_WeaponData[weaponid].szSound, 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	}
	else
	{
		if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
			gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, g_WeaponData[weaponid].szSoundSilen, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
		else
			gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, g_WeaponData[weaponid].szSoundSilen, 1.0, 2.0, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	}

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 4096, BULLET_PLAYER_45ACP, 0, 0, 2);
}

enum mp5n_e
{
	MP5N_IDLE1,
	MP5N_RELOAD,
	MP5N_DRAW,
	MP5N_SHOOT1,
	MP5N_SHOOT2,
	MP5N_SHOOT3
};

void EV_FireMP5N(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if(g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/pshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();

		if (g_WeaponData[weaponid].bHaveAnim)
		{
			if (!args->bparam2)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart2, g_WeaponData[weaponid].iAnimEnd2), 2);
		}
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(MP5N_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.25, 10, 10, 10, 3, velocity, false, 35);
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {34.0, -10.0, -11.0};
				
		if(g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		ShellVelocity[2] -= 50;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 13);

	if(g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 0.64, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_9MM, 0, 0, 2);
}

enum ak47_e
{
	AK47_IDLE1,
	AK47_RELOAD,
	AK47_DRAW,
	AK47_SHOOT1,
	AK47_SHOOT2,
	AK47_SHOOT3
};

void EV_FireAK47(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/rshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();


		if (g_WeaponData[weaponid].bHaveAnim)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(AK47_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.35, 20, 20, 20, 4, velocity, false, 35);
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {20.0, -8.0, -13.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];
		
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		ShellVelocity[2] -= 75;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 9);

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, 0.4, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_762MM, 0, 0, 2);
}

enum aug_e
{
	AUG_IDLE1,
	AUG_RELOAD,
	AUG_DRAW,
	AUG_SHOOT1,
	AUG_SHOOT2,
	AUG_SHOOT3
};

void EV_FireAug(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/rshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();

		if (g_WeaponData[weaponid].bHaveAnim)
		{
			if (!args->bparam2)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart2, g_WeaponData[weaponid].iAnimEnd2), 2);
		}
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(AUG_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.26, 15, 15, 15, 4, velocity, false, 35);
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {17.0, -8.0, -14.0};

		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];
				
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 1.25, ShellVelocity);
		ShellVelocity[2] -= 122;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 8);

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, 0.48, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_556MM, 0, 0, 2);
}

enum deagle_e
{
	DEAGLE_IDLE1,
	DEAGLE_SHOOT1,
	DEAGLE_SHOOT2,
	DEAGLE_SHOOT_EMPTY,
	DEAGLE_RELOAD,
	DEAGLE_DRAW
};

void EV_FireDeagle(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	int empty;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;

	ent = GetViewEntity();
	idx = args->entindex;
	empty = args->bparam1 != false;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][2];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/pshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();


		if (empty)
		{
			if (g_WeaponData[weaponid].iAnimEmpty)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(g_WeaponData[weaponid].iAnimEmpty, 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(DEAGLE_SHOOT_EMPTY, 2);
		}
		else
		{			
			if (g_WeaponData[weaponid].bHaveAnim)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(DEAGLE_SHOOT1 + gEngfuncs.pfnRandomLong(0, 1), 2);
		}

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 0, 0.25, 10, 10, 10, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 25, 0.3, 15, 15, 15, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 50, 0.2, 25, 25, 25, 2, velocity, false, 35);

	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {35.0, -11.0, -16.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];
		
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 0.75, ShellVelocity);
		ShellVelocity[2] += 25;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 5);

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 0.6, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_50AE, 0, 0, 2);
}

enum g3sg1_e
{
	G3SG1_IDLE,
	G3SG1_SHOOT,
	G3SG1_SHOOT2,
	G3SG1_RELOAD,
	G3SG1_DRAW
};

void EV_FireG3SG1(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/rshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();


		if (g_WeaponData[weaponid].bHaveAnim)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(G3SG1_SHOOT + gEngfuncs.pfnRandomLong(0, 1), 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.3, 35, 35, 35, 4, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 35, 0.35, 30, 30, 30, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 70, 0.3, 25, 25, 25, 2, velocity, false, 35);
		
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {20.0, -8.0, -10.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];

		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);
		
		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 1.5, ShellVelocity);
		ShellVelocity[2] -= 50.0;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 17);

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 0.6, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_762MM, 0, 0, 2);
}

enum sg550_e
{
	SG550_IDLE,
	SG550_SHOOT,
	SG550_SHOOT2,
	SG550_RELOAD,
	SG550_DRAW
};

void EV_FireSG550(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
	
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/rshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();

		
		if (g_WeaponData[weaponid].bHaveAnim)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(SG550_SHOOT + gEngfuncs.pfnRandomLong(0, 1), 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.3, 35, 35, 35, 4, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 35, 0.35, 30, 30, 30, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 70, 0.3, 25, 25, 25, 2, velocity, false, 35);
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {20.0, -8.0, -10.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];
		
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 1.5, ShellVelocity);
		ShellVelocity[2] -= 50.0;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 17);

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 0.6, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_556MM, 0, 0, 2);
}

enum glock18_e
{
	GLOCK18_IDLE1,
	GLOCK18_IDLE2,
	GLOCK18_IDLE3,
	GLOCK18_SHOOT,
	GLOCK18_SHOOT2,
	GLOCK18_SHOOT3,
	GLOCK18_SHOOT_EMPTY,
	GLOCK18_RELOAD,
	GLOCK18_DRAW,
	GLOCK18_HOLSTER,
	GLOCK18_ADD_SILENCER,
	GLOCK18_DRAW2,
	GLOCK18_RELOAD2
};

void EV_FireGlock18(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	int empty;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;


	ent = GetViewEntity();
	idx = args->entindex;
	empty = args->bparam1 != false;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][2];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/pshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();


		if (empty)
		{
			if (g_WeaponData[weaponid].iAnimEmpty)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(g_WeaponData[weaponid].iAnimEmpty, 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(GLOCK18_SHOOT_EMPTY, 2);
		}
		else
		{			
			if (g_WeaponData[weaponid].bHaveAnim)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(GLOCK18_SHOOT3, 2);
		}
		
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 0, 0.2, 10, 10, 10, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 40, 0.4, 20, 20, 20, 2, velocity, false, 35);

	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {36.0, -14.0, -14.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];		

		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 0.65, ShellVelocity);
		ShellVelocity[2] += 25.0;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 4);

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 4096, BULLET_PLAYER_9MM, 0, 0, 2);
}

enum m249_e
{
	M249_IDLE1,
	M249_SHOOT1,
	M249_SHOOT2,
	M249_RELOAD,
	M249_DRAW
};

int a = 0;

void EV_FireM249(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/rshell.mdl");

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);	

	if (EV_IsLocal(idx))
	{		
		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();

		if (g_WeaponData[weaponid].bHaveAnim)
		{
			if (!args->bparam2)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart2, g_WeaponData[weaponid].iAnimEnd2), 2);
		}
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(M249_SHOOT1 + gEngfuncs.pfnRandomLong(0, 1), 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.26, 15, 15, 15, 4, velocity, false, 35);

		g_iShotsFired++;
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {20.0, -10.0, -13.0};
		
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];
		
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		if (!(g_WeaponData[weaponid].iEffect & (1<<EFFECT_SHELL_M134)))
			VectorScale(ShellVelocity, 1.2, ShellVelocity);
		ShellVelocity[2] -= 75;		
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 10);

	if (g_WeaponData[weaponid].iEffect & (1<<EFFECT_SHELL_M134))
	{
		int shell2 = gEngfuncs.pEventAPI->EV_FindModelIndex("models/shell762_m134.mdl");

		if (EV_IsLocal(idx))
		{
			float vecScale[3] = {20.0, -10.0, -13.0};
			
			if (g_WeaponData[weaponid].bHaveShellVecScale)
			{
				vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
				vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
				vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
			}
	
			if (!lefthand)
				vecScale[2] = 0 - vecScale[2];
			
			EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);
	
			VectorCopy(ent->attachment[1], ShellOrigin);
			VectorScale(ShellVelocity, 1.1, ShellVelocity);
			ShellVelocity[2] -= 75;
		}
		else
			EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

			EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell2, TE_BOUNCE_SHELL, idx, 10);
	}	

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, 0.52, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_556MM, 0, 0, 2);
}

enum m3_e
{
	M3_IDLE,
	M3_FIRE1,
	M3_FIRE2,
	M3_RELOAD,
	M3_PUMP,
	M3_START_RELOAD,
	M3_DRAW,
	M3_HOLSTER
};

void EV_FireM3(struct event_args_s *args)
{	
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	int shell;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);

	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = 0;
	
	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;
	
		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();	
	
		if (g_WeaponData[weaponid].bHaveAnim)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(M3_FIRE1 + gEngfuncs.pfnRandomLong(0, 1), 2);
	
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.5, 25, 25, 25, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 25, 0.5, 20, 20, 20, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 50, 0.45, 15, 15, 15, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 75, 0.35, 7, 7, 7, 2, velocity, false, 35);
		
	}
	
	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {22.0, -9.0, -11.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}
	
		if (lefthand)
			vecScale[2] = 0 - vecScale[2];
		
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);
	
		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 1.25, ShellVelocity);
		ShellVelocity[2] -= 50;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);
	
	if (shell)
		EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_NULL, idx, 3);
	
	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 0.48, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = 0.0675;
	vSpread[1] = 0.0675;
	vSpread[2] = 0;

	if (args->fparam1)
	{
		vSpread[0] = args->fparam1;
		vSpread[1] = args->fparam2;
	}

	int shots = args->iparam1 ? args->iparam1 : 9;

	EV_HLDM_FireBullets(idx, forward, right, up, shots, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_BUCKSHOT, 0, 0, 1);
}

enum m4a1_e
{
	M4A1_IDLE,
	M4A1_SHOOT1,
	M4A1_SHOOT2,
	M4A1_SHOOT3,
	M4A1_RELOAD,
	M4A1_DRAW,
	M4A1_ATTACH_SILENCER,
	M4A1_UNSIL_IDLE,
	M4A1_UNSIL_SHOOT1,
	M4A1_UNSIL_SHOOT2,
	M4A1_UNSIL_SHOOT3,
	M4A1_UNSIL_RELOAD,
	M4A1_UNSIL_DRAW,
	M4A1_DETACH_SILENCER
};

void EV_FireM4A1(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	int silencer_on;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;

	ent = GetViewEntity();
	idx = args->entindex;
	silencer_on = args->bparam1;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/rshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();


		if (silencer_on)
		{
			if (g_WeaponData[weaponid].bHaveAnim)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart2, g_WeaponData[weaponid].iAnimEnd2), 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(M4A1_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);
		}
		else
		{			
			if (g_WeaponData[weaponid].bHaveAnim)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(M4A1_UNSIL_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);
		}

		if (silencer_on)
			EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.3, 16, 16, 16, 3, velocity, false, 35);
		else
			EV_HLDM_CreateSmoke(ent->attachment[2], forward, 3, 0.2, 16, 16, 16, 4, velocity, false, 35);
		
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {20.0, -8.0, -10.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];
		
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		ShellVelocity[2] -= 45;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 10);

	if (silencer_on)
	{
		if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
			gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
		else
			gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, g_WeaponData[weaponid].szSound, 1.0, 1.4, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	}
	else
	{
		if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
			gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, g_WeaponData[weaponid].szSoundSilen, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
		else
			gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, g_WeaponData[weaponid].szSoundSilen, 1.0, 1.4, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	}

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_556MM, 0, 0, 2);
}

enum mac10_e
{
	MAC10_IDLE1,
	MAC10_RELOAD,
	MAC10_DRAW,
	MAC10_SHOOT1,
	MAC10_SHOOT2,
	MAC10_SHOOT3
};

void EV_FireMac10(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/rshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();

		if (g_WeaponData[weaponid].bHaveAnim)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(MAC10_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 2, 0.25, 8, 8, 8, 3, velocity, false, 35);
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {32.0, -9.0, -11.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];

		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 0.75, ShellVelocity);
		ShellVelocity[2] -= 65;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 7);

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 0.72, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_9MM, 0, 0, 2);
}

enum p90_e
{
	P90_IDLE1,
	P90_RELOAD,
	P90_DRAW,
	P90_SHOOT1,
	P90_SHOOT2,
	P90_SHOOT3
};

void EV_FireP90(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/rshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();


		if (g_WeaponData[weaponid].bHaveAnim)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(P90_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.16, 7, 7, 7, 4, velocity, false, 35);
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {35.0, -16.0, -22.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 1.25, ShellVelocity);
		ShellVelocity[2] -= 50;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 10);

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 0.64, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_57MM, 0, 0, 2);
}

enum p228_e
{
	P228_IDLE,
	P228_SHOOT1,
	P228_SHOOT2,
	P228_SHOOT3,
	P228_SHOOT_EMPTY,
	P228_RELOAD,
	P228_DRAW
};

void EV_FireP228(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	int empty;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;

	ent = GetViewEntity();
	idx = args->entindex;
	empty = args->bparam1 != false;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][2];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/pshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();


		if (empty)
		{
			if (g_WeaponData[weaponid].iAnimEmpty)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(g_WeaponData[weaponid].iAnimEmpty, 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(P228_SHOOT_EMPTY, 2);
		}
		else
		{			
			if (g_WeaponData[weaponid].bHaveAnim)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(P228_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);
		}

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 0, 0.25, 10, 10, 10, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 25, 0.3, 15, 15, 15, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 50, 0.2, 20, 20, 20, 2, velocity, false, 35);
		
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {36.0, -14.0, -14.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];
		
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 0.75, ShellVelocity);
		ShellVelocity[2] += 35;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 4);

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_357SIG, 0, 0, 2);
}

enum awp_e
{
	AWP_IDLE,
	AWP_SHOOT1,
	AWP_SHOOT2,
	AWP_SHOOT3,
	AWP_RELOAD,
	AWP_DRAW
};

void EV_FireAWP(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();


		if (g_WeaponData[weaponid].bHaveAnim)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(AWP_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.5, 20, 20, 20, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 40, 0.5, 15, 15, 15, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 80, 0.5, 10, 10, 10, 2, velocity, false, 35);		
	}

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 0.28, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	VectorCopy(forward, vecAiming);

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_338MAG, 0, 0, 3);
}

enum scout_e
{
	SCOUT_IDLE,
	SCOUT_SHOOT,
	SCOUT_SHOOT2,
	SCOUT_RELOAD,
	SCOUT_DRAW
};

void EV_FireScout(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();

		
		if (g_WeaponData[weaponid].bHaveAnim)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(SCOUT_SHOOT + gEngfuncs.pfnRandomLong(0, 1), 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.45, 25, 25, 25, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 35, 0.45, 20, 20, 20, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 70, 0.45, 15, 15, 15, 2, velocity, false, 35);
		
	}

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 1.6, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	vSpread[0] = args->fparam1 / 1000.0;
	vSpread[1] = args->fparam2 / 1000.0;
	vSpread[2] = 0;

	VectorCopy(forward, vecAiming);

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_762MM, 0, 0, 3);
}

enum sg552_e
{
	SG552_IDLE1,
	SG552_RELOAD,
	SG552_DRAW,
	SG552_SHOOT1,
	SG552_SHOOT2,
	SG552_SHOOT3
};

void EV_FireSG552(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/rshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();

		
		if (g_WeaponData[weaponid].bHaveAnim)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(SG552_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.2, 18, 18, 18, 4, velocity, false, 35);
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {20.0, -8.0, -10.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];
		
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 1.65, ShellVelocity);
		ShellVelocity[2] -= 120;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 15);

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 0.4, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_556MM, 0, 0, 2);
}

enum tmp_e
{
	TMP_IDLE1,
	TMP_RELOAD,
	TMP_DRAW,
	TMP_SHOOT1,
	TMP_SHOOT2,
	TMP_SHOOT3
};

void EV_FireTMP(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/pshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();

		if (g_WeaponData[weaponid].bHaveAnim)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(TMP_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.2, 10, 10, 10, 3, velocity, false, 35);
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {32.0, -6.0, -11.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];
		
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 1.2, ShellVelocity);
		ShellVelocity[2] -= 50;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 15);

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 1.6, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_9MM, 0, 0, 2);
}

enum fiveseven_e
{
	FIVESEVEN_IDLE,
	FIVESEVEN_SHOOT1,
	FIVESEVEN_SHOOT2,
	FIVESEVEN_SHOOT_EMPTY,
	FIVESEVEN_RELOAD,
	FIVESEVEN_DRAW
};

void EV_FireFiveSeven(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	int empty;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;

	ent = GetViewEntity();
	idx = args->entindex;
	empty = args->bparam1 != false;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][2];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/pshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();


		if (empty)
		{
			if (g_WeaponData[weaponid].iAnimEmpty)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(g_WeaponData[weaponid].iAnimEmpty, 2);
			else			
				gEngfuncs.pEventAPI->EV_WeaponAnimation(FIVESEVEN_SHOOT_EMPTY, 2);
		}
		else
		{			
			if (g_WeaponData[weaponid].bHaveAnim)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(FIVESEVEN_SHOOT1 + gEngfuncs.pfnRandomLong(0, 1), 2);
		}

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 0, 0.25, 10, 10, 10, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 25, 0.3, 15, 15, 15, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 50, 0.2, 20, 20, 20, 2, velocity, false, 35);
		
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {36.0, -14.0, -14.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];
		
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 0.75, ShellVelocity);
		ShellVelocity[2] -= 35.0;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 4);

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_57MM, 0, 0, 2);
}

enum ump45_e
{
	UMP45_IDLE1,
	UMP45_RELOAD,
	UMP45_DRAW,
	UMP45_SHOOT1,
	UMP45_SHOOT2,
	UMP45_SHOOT3
};

void EV_FireUMP45(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/pshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();

		if (g_WeaponData[weaponid].bHaveAnim)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(UMP45_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.25, 10, 10, 10, 3, velocity, false, 35);
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {34.0, -10.0, -11.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];
		
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		ShellVelocity[2] -= 50;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 13);

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 0.64, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_45ACP, 0, 0, 2);
}

enum xm1014_e
{
	XM1014_IDLE,
	XM1014_FIRE1,
	XM1014_FIRE2,
	XM1014_RELOAD,
	XM1014_PUMP,
	XM1014_START_RELOAD,
	XM1014_DRAW
};

void EV_FireXM1014(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/shotgunshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();

		gEngfuncs.pEventAPI->EV_WeaponAnimation(XM1014_FIRE1 + gEngfuncs.pfnRandomLong(0, 1), 2);
		
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.45, 15, 15, 15, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 40, 0.35, 9, 9, 9, 2, velocity, false, 35);
		
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {22.0, -9.0, -11.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];
		
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 1.25, ShellVelocity);
		ShellVelocity[2] -= 50;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHOTSHELL, idx, 3);

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 0.52, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = 0.0725;
	vSpread[1] = 0.0725;
	vSpread[2] = 0;

	if (args->fparam1)
	{
		vSpread[0] = args->fparam1;
		vSpread[1] = args->fparam2;
	}

	int shots = args->iparam1 ? args->iparam1 : 6;

	EV_HLDM_FireBullets(idx, forward, right, up, shots, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_BUCKSHOT, 0, 0, 1);
}

enum elite_e
{
	ELITE_IDLE,
	ELITE_IDLE_LEFTEMPTY,
	ELITE_SHOOTLEFT1,
	ELITE_SHOOTLEFT2,
	ELITE_SHOOTLEFT3,
	ELITE_SHOOTLEFT4,
	ELITE_SHOOTLEFT5,
	ELITE_SHOOTLEFTLAST,
	ELITE_SHOOTRIGHT1,
	ELITE_SHOOTRIGHT2,
	ELITE_SHOOTRIGHT3,
	ELITE_SHOOTRIGHT4,
	ELITE_SHOOTRIGHT5,
	ELITE_SHOOTRIGHTLAST,
	ELITE_RELOAD,
	ELITE_DRAW
};

void (*g_pfnEV_FireElite)(struct event_args_s *args) = NULL;

void EV_FireEliteLeft(struct event_args_s *args)
{
	args->bparam1 = true;

	if (g_pfnEV_FireElite)
		return g_pfnEV_FireElite(args);

	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	int lefthand;
	float bullets_left;
	float time_diff;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	vec3_t vSpread;
	int weaponid;

	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = args->bparam1;
	bullets_left = args->iparam2;
	time_diff = args->fparam1;

	weaponid = g_iCustomWeapon[idx][2];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if(g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/pshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();


		if (lefthand)
		{
			if (bullets_left <= 1)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTLEFTLAST, 2);
			else if (time_diff >= 0.5)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTLEFT5, 2);
			else if (time_diff >= 0.4)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTLEFT4, 2);
			else if (time_diff >= 0.3)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTLEFT3, 2);
			else if (time_diff >= 0.2)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTLEFT2, 2);
			else if (time_diff >= 0.0)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTLEFT1, 2);

			EV_HLDM_CreateSmoke(ent->attachment[0], forward, 0, 0.25, 10, 10, 10, 3, velocity, false, 35);
			EV_HLDM_CreateSmoke(ent->attachment[0], forward, 25, 0.3, 15, 15, 15, 2, velocity, false, 35);
			EV_HLDM_CreateSmoke(ent->attachment[0], forward, 50, 0.2, 25, 25, 25, 2, velocity, false, 35);
			
		}
		else
		{
			if (bullets_left <= 1)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHTLAST, 2);
			else if (time_diff >= 0.5)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHT5, 2);
			else if (time_diff >= 0.4)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHT4, 2);
			else if (time_diff >= 0.3)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHT3, 2);
			else if (time_diff >= 0.2)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHT2, 2);
			else if (time_diff >= 0.0)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHT1, 2);

			EV_HLDM_CreateSmoke(ent->attachment[1], forward, 0, 0.25, 10, 10, 10, 3, velocity, false, 35);
			EV_HLDM_CreateSmoke(ent->attachment[1], forward, 25, 0.3, 15, 15, 15, 2, velocity, false, 35);
			EV_HLDM_CreateSmoke(ent->attachment[1], forward, 50, 0.2, 25, 25, 25, 2, velocity, false, 35);
			
		}
	}

	if (EV_IsLocal(idx))
	{
		if (lefthand)
		{
			EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 35.0, -11.0, -16.0, false);
			VectorCopy(ent->attachment[2], ShellOrigin);
		}
		else
		{
			EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 35.0, -11.0, 16.0, false);
			VectorCopy(ent->attachment[3], ShellOrigin);
		}

		VectorScale(ShellVelocity, 0.75, ShellVelocity);
		ShellVelocity[2] -= 25;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, 4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 5);

	if(g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam2;
	vSpread[1] = args->fparam1 / 100.0;
	vSpread[2] = 0;

	if (lefthand)
	{
		vecSrc[0] -= right[0] * 5;
		vecSrc[1] -= right[1] * 5;
		vecSrc[2] -= right[2] * 5;
	}
	else
	{
		vecSrc[0] += right[0] * 5;
		vecSrc[1] += right[1] * 5;
		vecSrc[2] += right[2] * 5;
	}

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_50AE, 0, 0, 2);
}

void EV_FireEliteRight(struct event_args_s *args)
{
	args->bparam1 = false;

	if (g_pfnEV_FireElite)
		return g_pfnEV_FireElite(args);

	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	float bullets_left;
	float time_diff;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	vec3_t vSpread;
	int weaponid;

	ent = GetViewEntity();
	idx = args->entindex;
	bullets_left = args->iparam2;
	time_diff = args->fparam1;
	weaponid = g_iCustomWeapon[idx][2];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if(g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/pshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();


		if (bullets_left <= 1)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHTLAST, 2);
		else if (time_diff >= 0.5)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHT5, 2);
		else if (time_diff >= 0.4)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHT4, 2);
		else if (time_diff >= 0.3)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHT3, 2);
		else if (time_diff >= 0.2)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHT2, 2);
		else if (time_diff >= 0.0)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHT1, 2);


		EV_HLDM_CreateSmoke(ent->attachment[1], forward, 0, 0.25, 10, 10, 10, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[1], forward, 25, 0.3, 15, 15, 15, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[1], forward, 50, 0.2, 25, 25, 25, 2, velocity, false, 35);
		
	}

	if (EV_IsLocal(idx))
	{
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 35.0, -11.0, 16.0, false);

		VectorCopy(ent->attachment[3], ShellOrigin);
		VectorScale(ShellVelocity, 0.75, ShellVelocity);
		ShellVelocity[2] -= 25;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, 4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 5);

	if(g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam2;
	vSpread[1] = args->fparam1 / 100.0;
	vSpread[2] = 0;

	vecSrc[0] += right[0] * 5;
	vecSrc[1] += right[1] * 5;
	vecSrc[2] += right[2] * 5;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_50AE, 0, 0, 2);
}

void EV_Balrog9ExplosionCallBack ( struct tempent_s *ent, float frametime, float currenttime )
{
	ent->entity.curstate.scale += 0.007;
	if(ent->die <= g_flTime + 0.3)
		ent->entity.curstate.renderamt -= 35;
}

void EV_Balrog7ExplosionCallBack ( struct tempent_s *ent, float frametime, float currenttime )
{
	ent->entity.curstate.scale += 0.0013;
	if(ent->die <= g_flTime + 0.4)
		ent->entity.curstate.renderamt -= 15;

	if(ent->entity.curstate.renderamt < 0)
		ent->entity.curstate.renderamt = 0;
}

void EV_SpearCallBack ( struct tempent_s *ent, float frametime, float currenttime )
{
	/*ent->entity.origin[0] += ent->entity.angles[0] / 360 * 2;
	ent->entity.origin[1] += ent->entity.angles[1] / 360 * 2;
	ent->entity.origin[2] += ent->entity.angles[2] / 360 * 7;*/
}

void EV_Knife(struct event_args_s *args)
{
	int idx;
	int weaponid;
	int effect = args->iparam1;
	vec3_t origin;
	
	idx = args->entindex;
	weaponid = g_iCustomWeapon[idx][args->iparam2];

	VectorCopy(args->origin, origin);

	if(effect & (1<<EVENT_PLAYSOUND))
	{
		if(g_WeaponData[weaponid].fSoundAttenuation)
			gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
		else
			gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	
		if (EV_IsLocal(idx) && args->bparam2)
			g_iShotsFired++;
	}

	if(effect & (1<<EVENT_BALROG_EXPLOSION))
	{
		int type = args->iparam2;
		
		if (!type)
		{
		struct model_s *pModel;		
		TEMPENTITY *pEnt;

		pModel = IEngineStudio.Mod_ForName("sprites/balrogcritical.spr", 0);

		pEnt = gEngfuncs.pEfxAPI->CL_TempEntAllocHigh(origin, pModel);
		pEnt->entity.curstate.rendermode = kRenderTransAdd;
		pEnt->entity.curstate.renderamt = 255;
		pEnt->entity.curstate.scale = 0.02;
		pEnt->die = g_flTime +0.6f;
		pEnt->flags |= FTENT_CLIENTCUSTOM;
		pEnt->callback = EV_Balrog9ExplosionCallBack;

		int id;
		gEngfuncs.CL_LoadModel("sprites/fexplo.spr", &id);
		origin[2] -= 15.0;
		gEngfuncs.pEfxAPI->R_Explosion(origin, id, 0.45, 60, TE_EXPLFLAG_NOSOUND);
		}
		else
		{
		struct model_s *pModel;		
		TEMPENTITY *pEnt;

		pModel = IEngineStudio.Mod_ForName("sprites/balrogcritical.spr", 0);

		pEnt = gEngfuncs.pEfxAPI->CL_TempEntAllocHigh(origin, pModel);
		pEnt->entity.curstate.rendermode = kRenderTransAdd;
		pEnt->entity.curstate.renderamt = 255;
		pEnt->entity.curstate.scale = 0.25;
		pEnt->die = g_flTime +1.0f;
		pEnt->flags |= FTENT_CLIENTCUSTOM;
		pEnt->callback = EV_Balrog7ExplosionCallBack;

		int id;
		gEngfuncs.CL_LoadModel("sprites/fexplo.spr", &id);
		origin[2] -= 15.0;
		gEngfuncs.pEfxAPI->R_Explosion(origin, id, 0.45, 30, TE_EXPLFLAG_NONE);

		if (EV_IsLocal(idx))
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart2, g_WeaponData[weaponid].iAnimEnd2), 2);
		}
	}

	if(effect & (1<<EVENT_SPEARGUN))
	{
		/*struct model_s *pModel;
		pModel = IEngineStudio.Mod_ForName("models/spear2.mdl", 0);*/

		/*for (int i=0;i<10;i++)
		{
			struct model_s *pModel;		
			TEMPENTITY *pEnt;

			pModel = IEngineStudio.Mod_ForName("models/spear2.mdl", 0);

			pEnt = gEngfuncs.pEfxAPI->CL_TempEntAllocHigh(origin, pModel);
			pEnt->die = g_flTime +10.0f;
			pEnt->entity.angles[0] = gEngfuncs.pfnRandomFloat(-360, 360);
			pEnt->entity.angles[1] = gEngfuncs.pfnRandomFloat(-360, 360);
			pEnt->entity.angles[2] = gEngfuncs.pfnRandomFloat(-360, 360);
			pEnt->flags |= FTENT_CLIENTCUSTOM | FTENT_GRAVITY;
			pEnt->callback = EV_SpearCallBack;
		}*/
		int id;

		float a[3], b[3];
		a[0] = a[1] = 10;
		a[2] = 200;
		b[0] = b[1] = b[2] = 0;
		gEngfuncs.CL_LoadModel("models/spear2.mdl", &id);
		gEngfuncs.pEfxAPI->R_BreakModel(origin, b, a, 100, 0, 10, id, 0);

		gEngfuncs.CL_LoadModel("sprites/flame_puff01.spr", &id);
		origin[2] += 20;
		gEngfuncs.pEfxAPI->R_Explosion(origin, id, 8.5, 80, TE_EXPLFLAG_NONE);
		//gEngfuncs.pEfxAPI->R_ParticleBurst(origin, 200, 100, 1);
		gEngfuncs.pEfxAPI->R_ParticleBurst(origin, 30, 50, 0.05);
		origin[2] -= 20;
		origin[0] += gEngfuncs.pfnRandomFloat(-32, 32);
		origin[1] += gEngfuncs.pfnRandomFloat(-32, 32);
		origin[2] += gEngfuncs.pfnRandomFloat(30, 35);
		gEngfuncs.CL_LoadModel("sprites/flame_puff01.spr", &id);
		gEngfuncs.pEfxAPI->R_Explosion(origin, id, 7.5, 80, TE_EXPLFLAG_NOSOUND);	

		/*struct model_s *pModel;		
		TEMPENTITY *pEnt;

		pModel = IEngineStudio.Mod_ForName("models/spear2.mdl", 0);

		pEnt = gEngfuncs.pEfxAPI->CL_TempEntAllocHigh(origin, pModel);
		pEnt->die = g_flTime +10.0f;
		pEnt->flags |= FTENT_CLIENTCUSTOM | FTENT_GRAVITY;*/
	}

	if(effect & (1<<EVENT_KNIFE))
	{
		weaponid = g_iCustomWeapon[idx][3];

		/*struct model_s *pModel;
		TEMPENTITY *pEnt;
		pModel = IEngineStudio.Mod_ForName("models/ef_dragonsword.mdl", 0);

		pEnt = gEngfuncs.pEfxAPI->CL_TempEntAllocHigh(origin, pModel);
		pEnt->entity.curstate.rendermode = kRenderTransAdd;
		pEnt->entity.curstate.renderamt = 254;
		pEnt->entity.curstate.scale = 1.0;

		Vector vecForw;
		gEngfuncs.pfnAngleVectors(g_vecAngles,vecForw,NULL,NULL);
		pEnt->entity.origin[0] = (g_vecEye[0] + vecForw[0]*5.0f);
		pEnt->entity.origin[1] = (g_vecEye[1] + vecForw[1]*5.0f);
		pEnt->entity.origin[2] = (g_vecEye[2] + vecForw[2]*5.0f);

		Engfunc_Call_AddVisibleEntity( &(pEnt->entity));*/		
		
		/*int iHitResult;
		bool bStab = args->bparam1;		

		if(!bStab)
		{			
			g_iAnim = (g_iAnim ++) % (g_WeaponData[weaponid].iAnimSwing[1] - g_WeaponData[weaponid].iAnimSwing[0] + 1);
			gEngfuncs.pEventAPI->EV_WeaponAnimation(g_iAnim + g_WeaponData[weaponid].iAnimSwing[0] - 1, 2);
			gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, "sound/weapons/knife_hit1.wav", 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
		}
		else if(!args->bparam2)
		{
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStab[0], g_WeaponData[weaponid].iAnimStab[1] +1), 2);
			gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, "sound/weapons/knife_hit1.wav", 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
		}
		else			
		{
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStabHit[0], g_WeaponData[weaponid].iAnimStabHit[1]), 2);
			gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, "sound/weapons/knife_hit1.wav", 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
		}*/

		int type = args->iparam2;
		int i = args->fparam2;
		int random;

		switch (type)
		{
		case 1:
			{
				random = g_WeaponData[weaponid].bRandomSound ? gEngfuncs.pfnRandomLong(0, g_WeaponData[weaponid].iSlash) : i;
				if (random > g_WeaponData[weaponid].iSlash) random = gEngfuncs.pfnRandomLong(0, g_WeaponData[weaponid].iSlash) - 1;
				gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_ITEM, g_WeaponData[weaponid].szSlash[random], 1.0, ATTN_NORM, 0, 98 + gEngfuncs.pfnRandomLong(0, 3));
				break;
			}
		case 2:
			{
				random = g_WeaponData[weaponid].bRandomSound ? gEngfuncs.pfnRandomLong(0, g_WeaponData[weaponid].iSlashHit) : i;
				if (random > g_WeaponData[weaponid].iSlashHit) random = gEngfuncs.pfnRandomLong(0, g_WeaponData[weaponid].iSlashHit);
				gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_ITEM, g_WeaponData[weaponid].szSlashHit[random], 1.0, ATTN_NORM, 0, 98 + gEngfuncs.pfnRandomLong(0, 3));
				break;
			}
		case 3:
			{
				random = g_WeaponData[weaponid].bRandomSound ? gEngfuncs.pfnRandomLong(0, g_WeaponData[weaponid].iWall) : i;
				if (random > g_WeaponData[weaponid].iWall) random = gEngfuncs.pfnRandomLong(0, g_WeaponData[weaponid].iWall);
				gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_ITEM, g_WeaponData[weaponid].szWall[random], 1.0, ATTN_NORM, 0, 98 + gEngfuncs.pfnRandomLong(0, 3));
				break;
			}
		case 4:
			{
				random = g_WeaponData[weaponid].bRandomSound ? gEngfuncs.pfnRandomLong(0, g_WeaponData[weaponid].iStab) : i;
				if (random > g_WeaponData[weaponid].iStab) random = gEngfuncs.pfnRandomLong(0, g_WeaponData[weaponid].iStab);
				gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_ITEM, g_WeaponData[weaponid].szStab[random], 1.0, ATTN_NORM, 0, 98 + gEngfuncs.pfnRandomLong(0, 3));
				break;
			}
		case 5:
			{
				random = g_WeaponData[weaponid].bRandomSound ? gEngfuncs.pfnRandomLong(0, g_WeaponData[weaponid].iStabHit) : i;
				if (random > g_WeaponData[weaponid].iStabHit) random = gEngfuncs.pfnRandomLong(0, g_WeaponData[weaponid].iStabHit);
				gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_ITEM, g_WeaponData[weaponid].szStabHit[random], 1.0, ATTN_NORM, 0, 98 + gEngfuncs.pfnRandomLong(0, 3));
				break;
			}
		case 6:
			{
				if(g_WeaponData[weaponid].szDraw[0])
					gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_ITEM, g_WeaponData[weaponid].szDraw, 1.0, ATTN_NORM, 0, 100);
				break;
			}
		}
	}


/*	if (EV_IsLocal(idx) && !effect)
		gEngfuncs.pEventAPI->EV_WeaponAnimation(args->iparam1, 2);*/
}

enum galil_e
{
	GALIL_IDLE1,
	GALIL_RELOAD,
	GALIL_DRAW,
	GALIL_SHOOT1,
	GALIL_SHOOT2,
	GALIL_SHOOT3
};

void EV_FireGalil(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;

	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 10000000.0;
	angles[1] += args->iparam2 / 10000000.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if(g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/rshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();

		if (g_WeaponData[weaponid].bHaveAnim)
		{
			if (!args->bparam2)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart2, g_WeaponData[weaponid].iAnimEnd2), 2);
		}
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(GALIL_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.26, 15, 15, 15, 4, velocity, false, 35);
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {20.0, -8.0, -10.0};
				
		if(g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];
		
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 1.25, ShellVelocity);
		ShellVelocity[2] -= 122;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 9);

	if(g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 0.4, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_762MM, 0, 0, 2);
}

enum famas_e
{
	FAMAS_IDLE1,
	FAMAS_RELOAD,
	FAMAS_DRAW,
	FAMAS_SHOOT1,
	FAMAS_SHOOT2,
	FAMAS_SHOOT3
};

void EV_FireFamas(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 10000000.0;
	angles[1] += args->iparam2 / 10000000.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if (g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/rshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();

		if (g_WeaponData[weaponid].bHaveAnim)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(FAMAS_SHOOT1 + gEngfuncs.pfnRandomLong(0, 2), 2);
	}

	if (EV_IsLocal(idx))
	{
		float vecScale[3] = {17.0, -8.0, -14.0};
				
		if (g_WeaponData[weaponid].bHaveShellVecScale)
		{
			vecScale[0] = g_WeaponData[weaponid].fShellVecScale[0];
			vecScale[1] = g_WeaponData[weaponid].fShellVecScale[1];
			vecScale[2] = g_WeaponData[weaponid].fShellVecScale[2];
		}

		if (lefthand)
			vecScale[2] = 0 - vecScale[2];
		
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, vecScale[0], vecScale[1], vecScale[2], true);

		VectorCopy(ent->attachment[1], ShellOrigin);
		VectorScale(ShellVelocity, 1.25, ShellVelocity);
		ShellVelocity[2] -= 122;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, -4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 8);

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 0.48, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_556MM, 0, 0, 2);
}

void EV_FireSprifle(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_MuzzleFlash();

		gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimEnd), 2);

		VectorScale(up, 0.4, up);

		EV_HLDM_CreateSmoke(ent->attachment[1], up, 80, 0.3, 120, 120, 120, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[1], up, 40, 0.2, 90, 90, 90, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[1], up, 30, 0.2, 60, 60, 60, 3, velocity, false, 35);		
	}

	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, 0.28, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	VectorCopy(forward, vecAiming);

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_338MAG, 0, 0, 3);
}

void EV_FireM1887XMAS(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	int lefthand;
	vec3_t vSpread;
	int weaponid;
		
	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = cl_righthand->value;
	weaponid = g_iCustomWeapon[idx][1];
	
	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);
	
	angles[0] += args->iparam1 / 100.0;
	angles[1] += args->iparam2 / 100.0;
	
	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	
	shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);		
	
	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_MuzzleFlash();

		if(g_iWeaponData[g_iWeapon].iClip > 1)		
			g_iAnim = gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart + 8, g_WeaponData[weaponid].iAnimEnd);
		else
			g_iAnim = gEngfuncs.pfnRandomLong(g_WeaponData[weaponid].iAnimStart, g_WeaponData[weaponid].iAnimStart + 7);

		gEngfuncs.pEventAPI->EV_WeaponAnimation(g_iAnim, 2);
	
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.5, 25, 25, 25, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 25, 0.5, 20, 20, 20, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 50, 0.45, 15, 15, 15, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 75, 0.35, 7, 7, 7, 2, velocity, false, 35);
		
	}
	


	char sound[64];
	int iAnim = g_iAnim - g_WeaponData[weaponid].iAnimStart;
	int iSound;
	if (iAnim >= 0)
		iSound = 1;
	if (iAnim >= 7)
		iSound = 2;
	if (iAnim >= 15)
		iSound = 3;

	if (EV_IsLocal(idx))
		sprintf(sound, "sound/weapons/%s-%d.wav", g_WeaponData[weaponid].szName, iSound);
	else
		sprintf(sound, "%s",g_WeaponData[weaponid].szSound);		
	
	if (g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, sound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, sound, 1.0, 0.48, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	
	EV_GetGunPosition(args, vecSrc, origin);
	
	VectorCopy(forward, vecAiming);
	
	vSpread[0] = 0.0675;
	vSpread[1] = 0.0675;
	vSpread[2] = 0;
	
	if (g_WeaponData[weaponid].bHaveShotGunSpread)
	{
		vSpread[0] = g_WeaponData[weaponid].fShotGunSpread[0];
		vSpread[1] = g_WeaponData[weaponid].fShotGunSpread[1];
		vSpread[2] = g_WeaponData[weaponid].fShotGunSpread[2];
	}
	
	int shots = 9;
	if (g_WeaponData[weaponid].iShotGunShots)
		shots = g_WeaponData[weaponid].iShotGunShots;
	
	EV_HLDM_FireBullets(idx, forward, right, up, shots, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_BUCKSHOT, 0, 0, 1);
}

enum skull4_e
{
	SKULL4_IDLE,
	SKULL4_IDLE_LEFT,
	SKULL4_LEFT1,
	SKULL4_LEFT2,
	SKULL4_LEFT_LAST,
	SKULL4_RIGHT1,
	SKULL4_RIGHT2,
	SKULL4_RIGHT_LAST,
	SKULL4_RELOAD,
	SKULL4_DRAW
};

void EV_FireSkull4Left(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	int lefthand;
	float bullets_left;
	float time_diff;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	vec3_t vSpread;
	int weaponid;

	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = args->bparam1;
	bullets_left = args->iparam2;
	time_diff = args->fparam1;

	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if(g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/rshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_MuzzleFlash();
			
		if (bullets_left <= 1)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(SKULL4_LEFT_LAST, 2);
		else if (gEngfuncs.pfnRandomLong(0,1))
			gEngfuncs.pEventAPI->EV_WeaponAnimation(SKULL4_LEFT1, 2);
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(SKULL4_LEFT2, 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 3, 0.35, 20, 20, 20, 4, velocity, false, 35);			
		
	}

	if (EV_IsLocal(idx))
	{
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 35.0, -11.0, -16.0, false);
		VectorCopy(ent->attachment[2], ShellOrigin);

		VectorScale(ShellVelocity, 0.75, ShellVelocity);
		ShellVelocity[2] -= 25;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, 4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 5);

	if(g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_556MM, 0, 0, 2);
}

void EV_FireSkull4Right(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	int lefthand;
	float bullets_left;
	float time_diff;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	vec3_t vSpread;
	int weaponid;

	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = args->bparam1;
	bullets_left = args->iparam2;
	time_diff = args->fparam1;

	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if(g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/rshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_MuzzleFlash();
			
		if (bullets_left <= 1)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(SKULL4_RIGHT_LAST, 2);
		else if (gEngfuncs.pfnRandomLong(0,1))
			gEngfuncs.pEventAPI->EV_WeaponAnimation(SKULL4_RIGHT1, 2);
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(SKULL4_RIGHT2, 2);

		EV_HLDM_CreateSmoke(ent->attachment[1], forward, 3, 0.35, 20, 20, 20, 4, velocity, false, 35);			
		
	}

	if (EV_IsLocal(idx))
	{
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 35.0, -11.0, 16.0, false);
		VectorCopy(ent->attachment[3], ShellOrigin);

		VectorScale(ShellVelocity, 0.75, ShellVelocity);
		ShellVelocity[2] -= 25;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, 4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 5);

	if(g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_556MM, 0, 0, 2);
}

void EV_FireDMP7A1Left(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	int lefthand;
	float bullets_left;
	float time_diff;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	vec3_t vSpread;
	int weaponid;

	ent = GetViewEntity();
	idx = args->entindex;
	lefthand = args->bparam1;
	bullets_left = args->iparam2;
	time_diff = args->fparam1;

	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if(g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/pshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();

		if (bullets_left <= 1)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTLEFTLAST, 2);
		else if (time_diff >= 0.5)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTLEFT5, 2);
		else if (time_diff >= 0.4)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTLEFT4, 2);
		else if (time_diff >= 0.3)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTLEFT3, 2);
		else if (time_diff >= 0.2)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTLEFT2, 2);
		else if (time_diff >= 0.0)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTLEFT1, 2);

		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 0, 0.25, 10, 10, 10, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 25, 0.3, 15, 15, 15, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[0], forward, 50, 0.2, 25, 25, 25, 2, velocity, false, 35);
			
	}

	if (EV_IsLocal(idx))
	{
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 35.0, -11.0, -16.0, false);
		VectorCopy(ent->attachment[2], ShellOrigin);

		VectorScale(ShellVelocity, 0.75, ShellVelocity);
		ShellVelocity[2] -= 25;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, 4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 5);

	if(g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	vecSrc[0] -= right[0] * 2;
	vecSrc[1] -= right[1] * 2;
	vecSrc[2] -= right[2] * 2;
	
	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_50AE, 0, 0, 2);
}

void EV_FireDMP7A1Right(struct event_args_s *args)
{
	args->bparam1 = false;

	if (g_pfnEV_FireElite)
		return g_pfnEV_FireElite(args);

	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	float bullets_left;
	float time_diff;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	vec3_t vSpread;
	int weaponid;

	ent = GetViewEntity();
	idx = args->entindex;
	bullets_left = args->iparam2;
	time_diff = args->fparam1;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if(g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/pshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();


		if (bullets_left <= 1)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHTLAST, 2);
		else if (time_diff >= 0.5)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHT5, 2);
		else if (time_diff >= 0.4)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHT4, 2);
		else if (time_diff >= 0.3)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHT3, 2);
		else if (time_diff >= 0.2)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHT2, 2);
		else if (time_diff >= 0.0)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(ELITE_SHOOTRIGHT1, 2);


		EV_HLDM_CreateSmoke(ent->attachment[1], forward, 0, 0.25, 10, 10, 10, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[1], forward, 25, 0.3, 15, 15, 15, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[1], forward, 50, 0.2, 25, 25, 25, 2, velocity, false, 35);
		
	}

	if (EV_IsLocal(idx))
	{
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 35.0, -11.0, 16.0, false);

		VectorCopy(ent->attachment[3], ShellOrigin);
		VectorScale(ShellVelocity, 0.75, ShellVelocity);
		ShellVelocity[2] -= 25;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, 4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 5);

	if(g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	vecSrc[0] += right[0] * 2;
	vecSrc[1] += right[1] * 2;
	vecSrc[2] += right[2] * 2;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_50AE, 0, 0, 2);
}

enum skull3_e
{
	SKULL3_IDLE,
	SKULL3_IDLE_LEFT,
	SKULL3_LEFT1,
	SKULL3_LEFT2,
	SKULL3_LEFT_LAST,
	SKULL3_RIGHT1,
	SKULL3_RIGHT2,
	SKULL3_RIGHT_LAST,
	SKULL3_RELOAD,
	SKULL3_DRAW,
	SKULL3_CHANGE_TO_B
};

void EV_FireSkull3Left(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	float bullets_left;
	float time_diff;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	vec3_t vSpread;
	int weaponid;

	ent = GetViewEntity();
	idx = args->entindex;
	bullets_left = args->iparam2;
	time_diff = args->fparam1;

	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if(g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/pshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();

		if (!args->bparam1)
		{
			if (bullets_left <= 1)
				gEngfuncs.pEventAPI->EV_WeaponAnimation(SKULL3_LEFT_LAST, 2);
			else if (gEngfuncs.pfnRandomLong(0,1))
				gEngfuncs.pEventAPI->EV_WeaponAnimation(SKULL3_LEFT1, 2);
			else
				gEngfuncs.pEventAPI->EV_WeaponAnimation(SKULL3_LEFT2, 2);
		}
		else
		{
			gEngfuncs.pEventAPI->EV_WeaponAnimation(gEngfuncs.pfnRandomLong(3,5), 2);
		}

		EV_HLDM_CreateSmoke(ent->attachment[1], forward, 0, 0.25, 10, 10, 10, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[1], forward, 25, 0.3, 15, 15, 15, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[1], forward, 50, 0.2, 25, 25, 25, 2, velocity, false, 35);
			
	}

	if (EV_IsLocal(idx))
	{
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 35.0, -11.0, 16.0, false);
		VectorCopy(ent->attachment[0], ShellOrigin);

		VectorScale(ShellVelocity, 0.75, ShellVelocity);
		ShellVelocity[2] -= 25;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, 4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 5);

	if(g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;
	
	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_50AE, 0, 0, 2);
}

void EV_FireSkull3Right(struct event_args_s *args)
{
	int idx;
	vec3_t origin;
	vec3_t angles;
	vec3_t velocity;
	float bullets_left;
	float time_diff;
	vec3_t ShellVelocity;
	vec3_t ShellOrigin;
	int shell;
	vec3_t vecSrc, vecAiming;
	vec3_t up, right, forward;
	cl_entity_t *ent;
	vec3_t vSpread;
	int weaponid;

	ent = GetViewEntity();
	idx = args->entindex;
	bullets_left = args->iparam2;
	time_diff = args->fparam1;
	weaponid = g_iCustomWeapon[idx][1];

	VectorCopy(args->origin, origin);
	VectorCopy(args->angles, angles);
	VectorCopy(args->velocity, velocity);

	gEngfuncs.pfnAngleVectors(angles, forward, right, up);
	if(g_WeaponData[weaponid].bHaveShellModel)
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex(g_WeaponData[weaponid].szShell);
	else
		shell = gEngfuncs.pEventAPI->EV_FindModelIndex("models/pshell.mdl");

	if (EV_IsLocal(idx))
	{
		g_iShotsFired++;

		EV_CustomEffect(args, g_WeaponData[weaponid].iEffect);
		EV_MuzzleFlash();

		if (bullets_left <= 1)
			gEngfuncs.pEventAPI->EV_WeaponAnimation(SKULL3_RIGHT_LAST, 2);
		else if (gEngfuncs.pfnRandomLong(0,1))
			gEngfuncs.pEventAPI->EV_WeaponAnimation(SKULL3_RIGHT1, 2);
		else
			gEngfuncs.pEventAPI->EV_WeaponAnimation(SKULL3_RIGHT2, 2);


		EV_HLDM_CreateSmoke(ent->attachment[2], forward, 0, 0.25, 10, 10, 10, 3, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[2], forward, 25, 0.3, 15, 15, 15, 2, velocity, false, 35);
		EV_HLDM_CreateSmoke(ent->attachment[2], forward, 50, 0.2, 25, 25, 25, 2, velocity, false, 35);
		
	}

	if (EV_IsLocal(idx))
	{
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 35.0, -11.0, 16.0, false);

		VectorCopy(ent->attachment[3], ShellOrigin);
		VectorScale(ShellVelocity, 0.75, ShellVelocity);
		ShellVelocity[2] -= 25;
	}
	else
		EV_GetDefaultShellInfo(args, origin, velocity, ShellVelocity, ShellOrigin, forward, right, up, 20.0, -12.0, 4.0, false);

	EV_EjectBrass(ShellOrigin, ShellVelocity, angles[YAW], shell, TE_BOUNCE_SHELL, idx, 5);

	if(g_WeaponData[g_iCustomWeapon[idx][1]].fSoundAttenuation)
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, g_WeaponData[weaponid].fSoundVolume, g_WeaponData[weaponid].fSoundAttenuation, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));
	else
		gEngfuncs.pEventAPI->EV_PlaySound(idx, origin, CHAN_WEAPON, args->bparam1?g_WeaponData[weaponid].szSound2:g_WeaponData[weaponid].szSound, 1.0, ATTN_NORM, 0, 94 + gEngfuncs.pfnRandomLong(0, 0xf));

	EV_GetGunPosition(args, vecSrc, origin);

	VectorCopy(forward, vecAiming);

	vSpread[0] = args->fparam1;
	vSpread[1] = args->fparam2;
	vSpread[2] = 0;

	EV_HLDM_FireBullets(idx, forward, right, up, 1, vecSrc, vecAiming, vSpread, 8192, BULLET_PLAYER_50AE, 0, 0, 2);
}