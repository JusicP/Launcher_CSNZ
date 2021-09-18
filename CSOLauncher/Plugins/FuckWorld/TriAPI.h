#ifndef _TRIAPI
#define _TRIAPI


extern int g_iVideoMode,g_iVideoQuality;

void Tri_BlendFunc(GLenum sfactor, GLenum dfactor);
void Tri_TexImage2D(GLenum target, GLint level, GLint internalformat, GLsizei width, GLsizei height, GLint border, GLenum format, GLenum type, const GLvoid *pixels);
void Tri_BindTexture(GLenum target, GLuint texture);
void Tri_DeleteTextures(GLsizei n, const GLuint *textures);
void Tri_TexParameteri(GLenum target, GLenum pname, GLint param);
void Tri_AlphaFunc(GLenum func, GLclampf ref);
void Tri_Enable(GLenum cap);
void Tri_Disable(GLenum cap);
void Tri_Extension_InstallHook(void);
void Tri_SetTextureParam(void);
void Tri_TexEnvf(GLenum target, GLenum pname, GLfloat param);



#endif