
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include "common/mathlib.h"
#include "engine/eiface.h"
#include "calcscreen.h"
#pragma warning (disable:4244)


#ifndef NULL
#define NULL ((void *)0)
#endif NULL
#define BOUND_VALUE(var,min,max) if((var)>(max)){(var)=(max);};if((var)<(min)){(var)=(min);}
float mainViewOrigin[3],mainViewAngles[3];
float displayCenterX=500, displayCenterY=350;
float fCurrentFOV; 

//===================================================================================
float VectorLength(const vec3_t v)
{
	return /*(float)*/sqrt(v[0]*v[0]+v[1]*v[1]+v[2]*v[2]);
}

//===================================================================================
inline float VectorAngle(const vec3_t a, const vec3_t b)
{
    float length_a = VectorLength(a);
	float length_b = VectorLength(b);
	float length_ab = length_a*length_b;
	if( length_ab==0.0 ){ return 0.0; }
	else                { return (double)(acos(DotProduct(a,b)/length_ab) * (180/FX_PI)); }
}

//===================================================================================
void MakeVector(const vec3_t ain, vec3_t vout)
{
	float pitch;
	float yaw;
	float tmp;		
	pitch = (ain[0] * FX_PI/180);
	yaw = (ain[1] * FX_PI/180);
	tmp = cos(pitch);
	vout[0] = (-tmp * -cos(yaw));
	vout[1] = (sin(yaw)*tmp);
	vout[2] = -sin(pitch);
}

//===================================================================================
void VectorRotateX(const vec3_t in, float angle, vec3_t out)
{
    float	a,c,s;
	a = (angle * FX_PI/180);
	c = cos(a);
	s = sin(a);
	out[0] = in[0];
	out[1] = c*in[1] - s*in[2];
	out[2] = s*in[1] + c*in[2];	
}

//===================================================================================
void VectorRotateY(const vec3_t in, float angle, vec3_t out)
{
	float a,c,s;
	a = (angle * FX_PI/180);
	c = cos(a);
	s = sin(a);
	out[0] = c*in[0] + s*in[2];
	out[1] = in[1];
	out[2] = -s*in[0] + c*in[2];
}

//===================================================================================
void VectorRotateZ(const vec3_t in, float angle, vec3_t out)
{
	float a,c,s;
	a = (angle * FX_PI/180);
	c = cos(a);
	s = sin(a);
	out[0] = c*in[0] - s*in[1];
	out[1] = s*in[0] + c*in[1];
	out[2] = in[2];
}

//===================================================================================
int CalcScreen(float in[3], float out[2])
{
	
	vec3_t aim;
	vec3_t newaim;
	vec3_t view;
	vec3_t tmp;
	float num;
	if(!in||!out){ return false; }
	VectorSubtract(in,mainViewOrigin,aim);	
	MakeVector(mainViewAngles,view);	
	if (VectorAngle(view,aim) > (fCurrentFOV/1.8))
	{
		return false;
	}	
	VectorRotateZ(aim,-mainViewAngles[1],newaim);
	VectorRotateY(newaim,-mainViewAngles[0],tmp);
	VectorRotateX(tmp,-mainViewAngles[2],newaim);
	/*if (newaim[0] <= 0)
	{
		return false;
	}*/
	if(fCurrentFOV==0.0){ return false; }
	num = /*(float)*/((displayCenterX/newaim[0])*(120.0/fCurrentFOV - 1.0/3.0));
	out[0] = displayCenterX - num*newaim[1];
	out[1] = displayCenterY - num*newaim[2];
	BOUND_VALUE(out[0],0,displayCenterX*2);
	BOUND_VALUE(out[1],0,displayCenterY*2);
	return true;
}
