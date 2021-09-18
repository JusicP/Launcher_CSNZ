#include "base.h"
#include "glut.h"
int g_iVideoMode;
int g_iVideoQuality;
// Frome HL.dll
void (APIENTRY *qglBlendFunc)(GLenum sfactor, GLenum dfactor);
void (APIENTRY *qglTexImage2D)(GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLint border, GLenum format, GLenum type, const GLvoid *pixels);
void (APIENTRY *qglBindTexture)(GLenum target, GLuint texture);
void (APIENTRY *qglDeleteTextures)(GLsizei n, const GLuint *textures);
void (APIENTRY *qglTexParameteri) (GLenum target, GLenum pname, GLint param);
void (APIENTRY *qglAlphaFunc)(GLenum func, GLclampf ref);
void (APIENTRY *qglEnable) (GLenum cap);
void (APIENTRY *qglDisable) (GLenum cap);
void (APIENTRY *qglTexEnvf) (GLenum target, GLenum pname, GLfloat param);

void Tri_Extension_InstallHook(void)
{
	DWORD dwAddress = *(DWORD *)((DWORD)gEngfuncs.pTriAPI->RenderMode + 0x47);
	qglBlendFunc = (void (APIENTRY *)(GLenum, GLenum))*(DWORD *)dwAddress;
	qglTexImage2D = (void (APIENTRY *)(GLenum, GLint, GLint, GLsizei, GLsizei, GLint, GLenum, GLenum, const GLvoid *))*(DWORD *)(dwAddress + 0x1EC);
	qglBindTexture = (void (APIENTRY *)(GLenum, GLuint))*(DWORD *)(dwAddress - 0x11C);
	qglDeleteTextures = (void (APIENTRY *)(GLsizei, const GLuint *))*(DWORD *)(dwAddress + 0x110);
	qglTexParameteri = (void (APIENTRY *) (GLenum target, GLenum pname, GLint param))*(DWORD *)(dwAddress - 0x524);
	qglAlphaFunc = (void (APIENTRY *) (GLenum func, GLclampf ref))*(DWORD *)(dwAddress - 0x374);
	qglEnable = (void (APIENTRY *) (GLenum cap))*(DWORD *)(dwAddress - 0x4BC);
	qglDisable = (void (APIENTRY *) (GLenum cap))*(DWORD *)(dwAddress + 0x380);
	qglTexEnvf = (void (APIENTRY *) (GLenum target, GLenum pname, GLfloat param))*(DWORD *)(dwAddress - 0x564);
}

void Tri_SetTextureParam(void)
{
	if(!g_iVideoMode)
	{
		Tri_TexParameteri ( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR );
		Tri_TexParameteri ( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR );
	}
	else if(!g_iVideoQuality)
	{
		Tri_TexParameteri ( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR );
		Tri_TexParameteri ( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR );
	}
	else 
	{
		Tri_TexParameteri ( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR );
		Tri_TexParameteri ( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR );
	}
}
void Tri_TexEnvf(GLenum target, GLenum pname, GLfloat param)
{
	if(g_iVideoMode)
	{
		glTexEnvf(target, pname,param);
	}
	else qglTexEnvf(target, pname,param);
}
void Tri_BlendFunc(GLenum sfactor, GLenum dfactor)
{
	if(g_iVideoMode)
	{
		glBlendFunc(sfactor, dfactor);
	}
	else qglBlendFunc(sfactor, dfactor);
}
void Tri_TexImage2D(GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLint border, GLenum format, GLenum type, const GLvoid *pixels)
{
	if(g_iVideoMode)
	{
		if(g_iVideoQuality)
		{
			glTexImage2D( target,  level,  internalformat,  width,  height,  border,  format,  type,pixels);
		}
		else
		{
			gluBuild2DMipmaps(target, internalformat, width, height, format, type, pixels);
		}
	}
	else 
	{
		qglTexImage2D( target,  level,  internalformat,  width,  height,  border,  format,  type,pixels);
	}
}
void Tri_BindTexture(GLenum target, GLuint texture)
{
	if(g_iVideoMode)
	{
		glBindTexture(target, texture);
	}
	else qglBindTexture(target, texture);
}

void Tri_DeleteTextures(GLsizei n, const GLuint *textures)
{
	if(g_iVideoMode)
	{
		glDeleteTextures(n, textures);
	}
	else qglDeleteTextures(n, textures);
}

void Tri_TexParameteri(GLenum target, GLenum pname, GLint param)
{
	if(g_iVideoMode)
	{
		glTexParameteri(target, pname,param);
	}
	else qglTexParameteri(target, pname,param);
}

void Tri_AlphaFunc(GLenum func, GLclampf ref)
{
	if(g_iVideoMode)
	{
		glAlphaFunc(func, ref);
	}
	else qglAlphaFunc(func, ref);
}

void Tri_Enable(GLenum cap)
{
	if(g_iVideoMode)
	{
		glEnable(cap);
	}
	else qglEnable(cap);
}
void Tri_Disable(GLenum cap)
{
	if(g_iVideoMode)
	{
		glDisable(cap);
	}
	else qglDisable(cap);
}