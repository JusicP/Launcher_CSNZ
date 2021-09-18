#ifndef _IMAGELIB
#define _IMAGELIB
typedef unsigned long	dword;
typedef struct imagedata_s
{
	int	width;
	int	height;
	int	rgba;
	int texid;
	char name[128];
	byte *data;
} imagedata_t;

typedef struct tga_s
{
	byte	id_length;
	byte	colormap_type;
	byte	image_type;
	word	colormap_index;
	word	colormap_length;
	byte	colormap_size;
	word	x_origin;
	word	y_origin;
	word	width;
	word	height;
	byte	pixel_size;
	byte	attributes;
} tga_t;

typedef struct bmp_s
{
	char	id[2];		// bmfh.bfType
	dword	fileSize;		// bmfh.bfSize
	dword	reserved0;	// bmfh.bfReserved1 + bmfh.bfReserved2
	dword	bitmapDataOffset;	// bmfh.bfOffBits
	dword	bitmapHeaderSize;	// bmih.biSize
	int	width;		// bmih.biWidth
	int	height;		// bmih.biHeight
	word	planes;		// bmih.biPlanes
	word	bitsPerPixel;	// bmih.biBitCount
	dword	compression;	// bmih.biCompression
	dword	bitmapDataSize;	// bmih.biSizeImage
	dword	hRes;		// bmih.biXPelsPerMeter
	dword	vRes;		// bmih.biYPelsPerMeter
	dword	colors;		// bmih.biClrUsed
	dword	importantColors;	// bmih.biClrImportant
} bmp_t;
bool Image_LoadImage(char *pName,imagedata_t *pImageData,int *iTexID);
bool Image_LoadTGA( const char *name, const byte *buffer, int FlipTga, imagedata_t *pData,int *TexID);
bool Image_LoadBMP( const char *name, const byte *buffer,imagedata_t *pData,int *TexID );
void Image_Resample32Lerp( const void *indata, int inwidth, int inheight, void *outdata, int outwidth, int outheight );
#endif