#ifndef CALCSCREEN_H
#define CALCSCREEN_H

#define FX_PI	3.141592

extern float mainViewOrigin[3], mainViewAngles[3];
extern float mainViewFov;
extern float displayCenterX, displayCenterY;
int CalcScreen(float in[3], float out[2]);
float VectorLength(const vec3_t v);
extern float fCurrentFOV;
#endif