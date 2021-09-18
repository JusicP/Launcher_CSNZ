#include "base.h"
#define LERPBYTE( i )	r = resamplerow1[i]; out[i] = (byte)(((( resamplerow2[i] - r ) * lerp)>>16 ) + r )

BYTE *Image_LoadBMP2( const char *name ,int *ww,int *hh);
int LoadBMP3 (const char* szFile, byte* ppbBits, BYTE** ppbPalettem, int &w, int &h);
byte* Bmp2RGBA(char* caFileName, int& w, int& h);

bool Image_LoadImage(char *pName,imagedata_t *pImageData,int *TexID)
{
	if(!FileExist(pName))
	{
		LogToFile("[加载纹理]纹理文件不存在:%s",pName);
		return false;
	}
	const char *szExt = FileExtension( pName );

	if(!strcmp(szExt,""))
	{
		LogToFile("[加载纹理]错误的扩展名:%s",szExt);
	}

	if(!strcmp(szExt,"tga"))
	{
		HANDLE hFile = CreateFile(pName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		DWORD dwLength;
		UINT length = (UINT)GetFileSize(hFile, NULL);
		byte *buffer = (byte *)malloc(length);
		::ReadFile(hFile, buffer, length, &dwLength, NULL);

		bool CallBack = Image_LoadTGA(pName,buffer,0,pImageData,TexID);
		CloseHandle(hFile);

		free(buffer);
		return CallBack;
	}
	if(!strcmp(szExt,"bmp"))
	{
		/*HANDLE hFile = CreateFile(pName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		DWORD dwLength;
		UINT length = (UINT)GetFileSize(hFile, NULL);
		byte *buffer = (byte *)malloc(length);
		::ReadFile(hFile, buffer, length, &dwLength, NULL);*/

		/*DWORD **data;
		data = NULL;
		Bmp2RGBA(pName, data, pImageData->width, pImageData->height);*/
		/*BYTE **data, **data2;
		data = NULL;
		data2 = NULL;
		LoadBMP3(pName, data, data2, pImageData->width, pImageData->height);*/

		byte *data = NULL;
		data = Bmp2RGBA(pName,pImageData->width, pImageData->height);

		sprintf(pImageData->name, "%s", pName);
		Tri_Enable(GL_TEXTURE_2D);
		Tri_BindTexture(GL_TEXTURE_2D, *TexID);
		Tri_SetTextureParam();

		Tri_TexImage2D(GL_TEXTURE_2D, 0, 3, pImageData->width, pImageData->height, 0, GL_RGB, GL_UNSIGNED_BYTE, data);

		pImageData->texid = *TexID;

		free(data);

		//bool CallBack = Image_LoadBMP2(pName,NULL,pImageData,TexID);
		//CloseHandle(hFile);
		
		//free(buffer);
		return true;
	}
	return false;
}

/*bool Image_LoadBMP( const char *name, const byte *buffer,imagedata_t *pData,int *TexID )
{
	FILE *file;
	short int bpp;
	short int planes;
	long i;
	long size;
	char temp;
	
	file = fopen(name, "rb");
	fseek(file, 18, SEEK_CUR);
	i = fread(&pData->width, 4, 1, file);
	i = fread(&pData->height, 4, 1, file);
	size = pData->width * pData->height * 3;
	i = fread(&bpp, 2, 1, file);
	i = fread(&planes, 2, 1, file);
	fseek(file,24, SEEK_CUR);
	pData->data = (byte *)malloc(size);
	i = fread(pData->data, size, 1, file);
	for(i = 0; i < size; i+=3)
	{
		temp = pData->data[i];
		pData->data[i] = pData->data[i+2];
		pData->data[i+2] = temp;
	}
	fclose(file);
	sprintf(pData->name,"%s",name);
	Tri_Enable(GL_TEXTURE_2D);
	Tri_BindTexture(GL_TEXTURE_2D, *TexID);
	Tri_SetTextureParam();
	pData->texid = *TexID;
	//reverse data
	byte *pReversed = (byte *)malloc(size);
	for(int i=size-3;i>=0;i-=3)
	{
		pReversed[size-i + 0] =  pData->data[i + 0];
		pReversed[size-i + 1] =  pData->data[i + 1];
		pReversed[size-i + 2] =  pData->data[i + 2];
	}
	
	Tri_TexImage2D(GL_TEXTURE_2D, 0, 3, pData->width, pData->height, 0, GL_RGB, GL_UNSIGNED_BYTE, pReversed);
	
	free(pData->data);
	pData->data = NULL;
	
	LogToFile("成功加载BMP纹理图片2:[宽度%d 高度%d 色深:%d 分配纹理ID%d]",pData->width, pData->height,bpp,*TexID);
	return true;
}*/

BYTE *Image_LoadBMP2( const char *name ,int *ww,int *hh)
{
	FILE *file;
	short int bpp,bytes_per_row,bpp2;
	short int planes;
	long i;
	char temp;
	int w,h;
	UCHAR *palette;
	int imagesize;
	int a;
	
	file = fopen(name, "rb");
	fseek(file, 18, SEEK_CUR);
	i = fread(&w, 4, 1, file);
	i = fread(&h, 4, 1, file);
	i = fread(&planes, 2, 1, file);
	i = fread(&bpp, 2, 1, file);
	i = fread(&a, 4, 1, file);
	i = fread(&imagesize, 4, 1, file);
	
	*ww = w;
	*hh = h;
	
	fseek(file,16, SEEK_CUR);
	
	if ( bpp == 8 )
	{
		palette = (UCHAR*) malloc( 256 * 4 * sizeof( UCHAR ) );
		
		fread( palette, sizeof( UCHAR ), 256 * 4, file );
	}	
	byte *data = (byte *)malloc(imagesize);
	byte *data2 = (byte *)malloc(w * h* 4);
	fread(data, imagesize, 1, file);
	int iCount = 0;
	UCHAR*	pixel;
	
	for(int x = 0;x<h;x++)
	{
		for(int y=0;y<w;y++)
		{
			bpp2 = bpp >> 3;
			bytes_per_row = imagesize / h;
			pixel = data + ( ( h - y - 1 ) * bytes_per_row + x * bpp2 );
			if ( bpp == 8 ) pixel = palette + *pixel * 4;
			data2[iCount + 0 ] = *( pixel + 2 );
			data2[iCount + 1 ] = *( pixel + 1 );
			data2[iCount + 2 ] = *( pixel + 0 );
			data2[iCount + 3 ] = 255;
			iCount += 4;
		}
	}
	free(data);
	fclose(file);
	return data2;
}

bool Image_LoadTGA( const char *name, const byte *buffer, int FlipTga, imagedata_t *pData,int *TexID)
{
	LogToFile("正在处理TGA纹理:%s", name );
	int	i, columns, rows, row_inc, row, col;
	byte	*buf_p, *pixbuf, *targa_rgba;
	byte	palette[256][4], red = 0, green = 0, blue = 0, alpha = 0;
	int	readpixelcount, pixelcount;
	qboolean	compressed;
	tga_t	targa_header;

	buf_p = (byte *)buffer;
	targa_header.id_length = *buf_p++;
	targa_header.colormap_type = *buf_p++;
	targa_header.image_type = *buf_p++;

	targa_header.colormap_index = buf_p[0] + buf_p[1] * 256;		buf_p += 2;
	targa_header.colormap_length = buf_p[0] + buf_p[1] * 256;		buf_p += 2;
	targa_header.colormap_size = *buf_p;				buf_p += 1;
	targa_header.x_origin = *(short *)buf_p;			buf_p += 2;
	targa_header.y_origin = *(short *)buf_p;			buf_p += 2;
	targa_header.width = *(short *)buf_p;		buf_p += 2;
	targa_header.height = *(short *)buf_p;		buf_p += 2;
	targa_header.pixel_size = *buf_p++;
	targa_header.attributes = *buf_p++;
	if( targa_header.id_length != 0 ) buf_p += targa_header.id_length;	// skip TARGA image comment

	if( targa_header.image_type == 1 || targa_header.image_type == 9 )
	{
		// uncompressed colormapped image
		if( targa_header.pixel_size != 8 )
		{
			LogToFile("TGA处理错误信息:Only 8 bit images supported for type 1 and 9");
			return false;
		}
		if( targa_header.colormap_length != 256 )
		{
			LogToFile("TGA处理错误信息:Only 8 bit colormaps are supported for type 1 and 9");
			return false;
		}
		if( targa_header.colormap_index )
		{
			LogToFile("TGA处理错误信息:colormap_index is not supported for type 1 and 9");
			return false;
		}
		if( targa_header.colormap_size == 24 )
		{
			for( i = 0; i < targa_header.colormap_length; i++ )
			{
				palette[i][2] = *buf_p++;
				palette[i][1] = *buf_p++;
				palette[i][0] = *buf_p++;
				palette[i][3] = 255;
			}
		}
		else if( targa_header.colormap_size == 32 )
		{
			for( i = 0; i < targa_header.colormap_length; i++ )
			{
				palette[i][2] = *buf_p++;
				palette[i][1] = *buf_p++;
				palette[i][0] = *buf_p++;
				palette[i][3] = *buf_p++;
			}
		}
		else
		{
			LogToFile("TGA处理错误信息:only 24 and 32 bit colormaps are supported for type 1 and 9");
			return false;
		}
	}
	else if( targa_header.image_type == 2 || targa_header.image_type == 10 )
	{
		// uncompressed or RLE compressed RGB
		if( targa_header.pixel_size != 32 && targa_header.pixel_size != 24 )
		{
			LogToFile( "TGA处理错误信息:Only 32 or 24 bit images supported for type 2 and 10");
			return false;
		}
	}
	else if( targa_header.image_type == 3 || targa_header.image_type == 11 )
	{
		// uncompressed greyscale
		if( targa_header.pixel_size != 8 )
		{
			LogToFile( "TGA处理错误信息:Only 8 bit images supported for type 3 and 11");
			return false;
		}
	}

	columns = targa_header.width;
	rows = targa_header.height;

	int size = columns * rows * 4;
	targa_rgba = (byte *)malloc (size);

	// if bit 5 of attributes isn't set, the image has been stored from bottom to top
	if( FlipTga && targa_header.attributes & 0x20 )
	{
		pixbuf = targa_rgba;
		row_inc = 0;
	}
	else
	{
		pixbuf = targa_rgba + ( rows - 1 ) * columns * 4;
		row_inc = -columns * 4 * 2;
	}

	compressed = ( targa_header.image_type == 9 || targa_header.image_type == 10 || targa_header.image_type == 11 );
	for( row = col = 0; row < rows; )
	{
		pixelcount = 0x10000;
		readpixelcount = 0x10000;

		if( compressed )
		{
			pixelcount = *buf_p++;
			if( pixelcount & 0x80 )  // run-length packet
				readpixelcount = 1;
			pixelcount = 1 + ( pixelcount & 0x7f );
		}

		while( pixelcount-- && ( row < rows ) )
		{
			if( readpixelcount-- > 0 )
			{
				switch( targa_header.image_type )
				{
				case 1:
				case 9:
					// colormapped image
					blue = *buf_p++;
					red = palette[blue][0];
					green = palette[blue][1];
					alpha = palette[blue][3];
					blue = palette[blue][2];
					//if( alpha != 255 ) image.flags |= IMAGE_HAS_ALPHA;
					break;
				case 2:
				case 10:
					// 24 or 32 bit image
					blue = *buf_p++;
					green = *buf_p++;
					red = *buf_p++;
					alpha = 255;
					if( targa_header.pixel_size == 32 )
					{
						alpha = *buf_p++;
						//if( alpha != 255 )
							//image.flags |= IMAGE_HAS_ALPHA;
					}
					break;
				case 3:
				case 11:
					// greyscale image
					blue = green = red = *buf_p++;
					alpha = 255;
					break;
				}
			}


			*pixbuf++ = red;
			*pixbuf++ = green;
			*pixbuf++ = blue;
			*pixbuf++ = alpha;
			if( ++col == columns )
			{
				row++;
				col = 0;
				pixbuf += row_inc;
			}
		}
	}

	// Create Texture

	pData->width = targa_header.width;
	pData->rgba = 4;
	pData->height = targa_header.height;
	pData->texid = *TexID;
	sprintf(pData->name,"%s",name);
	
	Tri_Enable(GL_TEXTURE_2D);
	Tri_BindTexture(GL_TEXTURE_2D, *TexID);
	Tri_SetTextureParam();
	Tri_TexImage2D(GL_TEXTURE_2D, 0, 4, pData->width, pData->height, 0, GL_RGBA, GL_UNSIGNED_BYTE, targa_rgba);
	
	if(strstr(name,"tattoo"))
	{
		pData->data = targa_rgba;
	}
	else
	{
		free(targa_rgba);
		pData->data = NULL;
	}
	LogToFile("成功加载TGA纹理图片:[宽度%d 高度%d 分配纹理ID%d]",pData->width, pData->height,*TexID);
	return true;
}
static void Image_Resample32LerpLine( const byte *in, byte *out, int inwidth, int outwidth )
{
	int	j, xi, oldx = 0, f, fstep, endx, lerp;

	fstep = (int)(inwidth * 65536.0f / outwidth);
	endx = (inwidth-1);

	for( j = 0, f = 0; j < outwidth; j++, f += fstep )
	{
		xi = f>>16;
		if( xi != oldx )
		{
			in += (xi - oldx) * 4;
			oldx = xi;
		}
		if( xi < endx )
		{
			lerp = f & 0xFFFF;
			*out++ = (byte)((((in[4] - in[0]) * lerp)>>16) + in[0]);
			*out++ = (byte)((((in[5] - in[1]) * lerp)>>16) + in[1]);
			*out++ = (byte)((((in[6] - in[2]) * lerp)>>16) + in[2]);
			*out++ = (byte)((((in[7] - in[3]) * lerp)>>16) + in[3]);
		}
		else // last pixel of the line has no pixel to lerp to
		{
			*out++ = in[0];
			*out++ = in[1];
			*out++ = in[2];
			*out++ = in[3];
		}
	}
}
void Image_Resample32Lerp( const void *indata, int inwidth, int inheight, void *outdata, int outwidth, int outheight )
{
	int	i, j, r, yi, oldy = 0, f, fstep, lerp, endy = (inheight - 1);
	int	inwidth4 = inwidth * 4;
	int	outwidth4 = outwidth * 4;
	const byte *inrow;
	byte	*out;
	byte	*resamplerow1;
	byte	*resamplerow2;

	out = (byte *)outdata;
	fstep = (int)(inheight * 65536.0f/outheight);

	resamplerow1 = (byte *)malloc( outwidth * 4 * 2);
	resamplerow2 = resamplerow1 + outwidth * 4;

	inrow = (const byte *)indata;

	Image_Resample32LerpLine( inrow, resamplerow1, inwidth, outwidth );
	Image_Resample32LerpLine( inrow + inwidth4, resamplerow2, inwidth, outwidth );

	for( i = 0, f = 0; i < outheight; i++, f += fstep )
	{
		yi = f>>16;

		if( yi < endy )
		{
			lerp = f & 0xFFFF;
			if( yi != oldy )
			{
				inrow = (byte *)indata + inwidth4 * yi;
				if (yi == oldy+1) memcpy( resamplerow1, resamplerow2, outwidth4 );
				else Image_Resample32LerpLine( inrow, resamplerow1, inwidth, outwidth );
				Image_Resample32LerpLine( inrow + inwidth4, resamplerow2, inwidth, outwidth );
				oldy = yi;
			}
			j = outwidth - 4;
			while( j >= 0 )
			{
				LERPBYTE( 0);
				LERPBYTE( 1);
				LERPBYTE( 2);
				LERPBYTE( 3);
				LERPBYTE( 4);
				LERPBYTE( 5);
				LERPBYTE( 6);
				LERPBYTE( 7);
				LERPBYTE( 8);
				LERPBYTE( 9);
				LERPBYTE(10);
				LERPBYTE(11);
				LERPBYTE(12);
				LERPBYTE(13);
				LERPBYTE(14);
				LERPBYTE(15);
				out += 16;
				resamplerow1 += 16;
				resamplerow2 += 16;
				j -= 4;
			}
			if( j & 2 )
			{
				LERPBYTE( 0);
				LERPBYTE( 1);
				LERPBYTE( 2);
				LERPBYTE( 3);
				LERPBYTE( 4);
				LERPBYTE( 5);
				LERPBYTE( 6);
				LERPBYTE( 7);
				out += 8;
				resamplerow1 += 8;
				resamplerow2 += 8;
			}
			if( j & 1 )
			{
				LERPBYTE( 0);
				LERPBYTE( 1);
				LERPBYTE( 2);
				LERPBYTE( 3);
				out += 4;
				resamplerow1 += 4;
				resamplerow2 += 4;
			}
			resamplerow1 -= outwidth4;
			resamplerow2 -= outwidth4;
		}
		else
		{
			if( yi != oldy )
			{
				inrow = (byte *)indata + inwidth4*yi;
				if( yi == oldy + 1 ) memcpy( resamplerow1, resamplerow2, outwidth4 );
				else Image_Resample32LerpLine( inrow, resamplerow1, inwidth, outwidth);
				oldy = yi;
			}
			memcpy( out, resamplerow1, outwidth4 );
		}
	}

	free( resamplerow1 );
	resamplerow1 = NULL;
	resamplerow2 = NULL;
}



/*bool Image_LoadBMP2( const char *name, const byte *buffer,imagedata_t *pData,int *TexID )
{
	LogToFile("正在处理BMP纹理:%s", name );
	byte	*buf_p, *pixbuf;
	byte	palette[256][4];
	int	columns, column, rows, row, bpp = 1;
	int	cbPalBytes = 0, padSize = 0, bps = 0;
	bmp_t	bhdr;

	buf_p = (byte *)buffer;
	bhdr.id[0] = *buf_p++;
	bhdr.id[1] = *buf_p++;				// move pointer
	bhdr.fileSize = *(long *)buf_p;	buf_p += 4;
	bhdr.reserved0 = *(long *)buf_p;	buf_p += 4;
	bhdr.bitmapDataOffset = *(long *)buf_p;	buf_p += 4;
	bhdr.bitmapHeaderSize = *(long *)buf_p;	buf_p += 4;
	bhdr.width = *(long *)buf_p;		buf_p += 4;
	bhdr.height = *(long *)buf_p;		buf_p += 4;
	bhdr.planes = *(short *)buf_p;	buf_p += 2;
	bhdr.bitsPerPixel = *(short *)buf_p;	buf_p += 2;
	bhdr.compression = *(long *)buf_p;	buf_p += 4;
	bhdr.bitmapDataSize = *(long *)buf_p;	buf_p += 4;
	bhdr.hRes = *(long *)buf_p;		buf_p += 4;
	bhdr.vRes = *(long *)buf_p;		buf_p += 4;
	bhdr.colors = *(long *)buf_p;		buf_p += 4;
	bhdr.importantColors = *(long *)buf_p;	buf_p += 4;

	// bogus file header check
	if( bhdr.reserved0 != 0 ) return false;
	if( bhdr.planes != 1 ) return false;

	if( memcmp( bhdr.id, "BM", 2 ))
	{
		LogToFile("BMP处理错误信息: only Windows-style BMP files supported (%s)\n", name );
		return false;
	} 

	if( bhdr.bitmapHeaderSize != 0x28 )
	{
		LogToFile("BMP处理错误信息: invalid header size %i\n", bhdr.bitmapHeaderSize );
		return false;
	}
          
	// bogus compression?  Only non-compressed supported.
	if( bhdr.compression != BI_RGB ) 
	{
		LogToFile("BMP处理错误信息: only uncompressed BMP files supported (%s)\n", name );
		return false;
	}

	pData->width = columns = bhdr.width;
	pData->height = rows = abs( bhdr.height );      
	//pData->height = 150;
	//pData->width = 500;
	//rows = 150;
	//columns = 150;

	if( bhdr.bitsPerPixel <= 8 )
	{
		// figure out how many entires are actually in the table
		if( bhdr.colors == 0 )
		{
			bhdr.colors = 256;
			cbPalBytes = (1 << bhdr.bitsPerPixel) * sizeof( RGBQUAD );
		}
		else cbPalBytes = bhdr.colors * sizeof( RGBQUAD );
	}

	memcpy( palette, buf_p, cbPalBytes );

	//image.type = PF_RGBA_32;
	bpp = 4;

	buf_p += cbPalBytes;
	int size = pData->width * pData->height * bpp;
	pData->data = (byte *)malloc( size );
	bps = pData->width * (bhdr.bitsPerPixel >> 3);

	switch( bhdr.bitsPerPixel )
	{
	case 1:
		padSize = (( 32 - ( bhdr.width % 32 )) / 8 ) % 4;
		break;
	case 4:
		padSize = (( 8 - ( bhdr.width % 8 )) / 2 ) % 4;
		break;
	case 16:
		padSize = ( 4 - ( pData->width * 2 % 4 )) % 4;
		break;
	case 8:
	case 24:
		padSize = ( 4 - ( bps % 4 )) % 4;
		break;
	}

	for( row = rows - 1; row >= 0; row-- )
	{
		//byte *x = (row * (columns) * bpp);
		pixbuf = pData->data + (row * (columns-12) * bpp);

		for( column = 0; column < columns; column++ )
		{
			if(column<300)
			{
				*pixbuf++ = 0;
				*pixbuf++ = 0;
				*pixbuf++ = 0;
				*pixbuf++ = 0;
			}

			
			byte	red, green, blue, alpha;
			word	shortPixel;
			int	c, k, palIndex;

			switch( bhdr.bitsPerPixel )
			{
			case 1:
				alpha = *buf_p++;
				column--;	// ingnore main iterations
				for( c = 0, k = 128; c < 8; c++, k >>= 1 )
				{
					red = green = blue = (!!(alpha & k) == 1 ? 0xFF : 0x00);
					*pixbuf++ = red;
					*pixbuf++ = green;
					*pixbuf++ = blue;
					*pixbuf++ = 0x00;
					if( ++column == columns )
						break;
				}
				break;
			case 4:
				alpha = *buf_p++;
				palIndex = alpha >> 4;

				*pixbuf++ = red = palette[palIndex][2];
				*pixbuf++ = green = palette[palIndex][1];
				*pixbuf++ = blue = palette[palIndex][0];
				*pixbuf++ = palette[palIndex][3];
				if( ++column == columns ) break;
				palIndex = alpha & 0x0F;

				*pixbuf++ = red = palette[palIndex][2];
				*pixbuf++ = green = palette[palIndex][1];
				*pixbuf++ = blue = palette[palIndex][0];
				*pixbuf++ = palette[palIndex][3];
				
				break;
			case 8:
				palIndex = *buf_p++;
				red = palette[palIndex][2];
				green = palette[palIndex][1];
				blue = palette[palIndex][0];
				alpha = palette[palIndex][3];

				*pixbuf++ = red;
				*pixbuf++ = green;
				*pixbuf++ = blue;
				*pixbuf++ = alpha;

				break;
			case 16:
				shortPixel = *(word *)buf_p, buf_p += 2;
				*pixbuf++ = blue = (shortPixel & ( 31 << 10 )) >> 7;
				*pixbuf++ = green = (shortPixel & ( 31 << 5 )) >> 2;
				*pixbuf++ = red = (shortPixel & ( 31 )) << 3;
				*pixbuf++ = 0xff;
				break;
			case 24:
				blue = *buf_p++;
				green = *buf_p++;
				red = *buf_p++;
				*pixbuf++ = red;
				*pixbuf++ = green;
				*pixbuf++ = blue;
				*pixbuf++ = 0xFF;
				break;
			default:
				LogToFile("BMP处理错误信息: illegal pixel_size (%s)\n", name );
				return false;
			}
		}
		buf_p += padSize;	// actual only for 4-bit bmps
	}
	sprintf(pData->name,"%s",name);
	Tri_Enable(GL_TEXTURE_2D);
	Tri_BindTexture(GL_TEXTURE_2D, *TexID);
	Tri_SetTextureParam();
	pData->texid = *TexID;
	Tri_TexImage2D(GL_TEXTURE_2D, 0, 4, pData->width, pData->height, 0, GL_RGBA, GL_UNSIGNED_BYTE, pData->data);

	free(pData->data);
	pData->data = NULL;

	LogToFile("成功加载BMP纹理图片:[宽度%d 高度%d 色深:%d 分配纹理ID%d]",pData->width, pData->height,bhdr.bitsPerPixel,*TexID);
	return true;
}
*/

byte* Bmp2RGBA(char* caFileName, int& w, int& h)
{
	byte *pdat = NULL;

    FILE* pf = fopen(caFileName, "rb");
    if (pf == NULL) 
        return pdat;
 
    BITMAPFILEHEADER bm;
    fread(&bm, 1, sizeof(BITMAPFILEHEADER), pf);
 
    if (bm.bfType!=*(WORD*)"BM")
    {    
        fclose(pf);
        return pdat;
    }
    BITMAPINFOHEADER bmif;
    fread(&bmif, 1, sizeof(BITMAPINFOHEADER), pf);
    int bmx = bmif.biWidth;
    int bmy = bmif.biHeight>0?bmif.biHeight:(-bmif.biHeight);
 
    if (bmif.biBitCount < 8 || bmif.biCompression != 0) 
    {
        fclose(pf);
        return pdat;
    }
 
    RGBQUAD *pRgb = NULL;
    if (bmif.biBitCount == 8) // 256色bmp
    {
        pRgb = (RGBQUAD*) new BYTE[bmif.biClrUsed * sizeof(RGBQUAD)];
        fread(pRgb, bmif.biClrUsed * sizeof(RGBQUAD), 1, pf);
    }
 
    BOOL bAlpha = FALSE;
    if (bmif.biBitCount == 32)    bAlpha = TRUE;// 带Alpha通道
 
    DWORD dwRealWidth = (((bmx*bmif.biBitCount)+31)>>5)<<2;
    int iBitSteps = bmif.biBitCount>>3;
    DWORD iSize = dwRealWidth*bmy;
 
    BYTE* pBmpData = NULL;
    int readlines = bmy;
    int readszie = iSize;
    int readtimes = bmy/readlines;
    if (iSize > 128*1024*1024)
    {
        readlines = (128*1024*1024/dwRealWidth);
        readszie = readlines*dwRealWidth;
        readtimes = bmy/readlines + 1;
    }
 
 
    pBmpData = new BYTE[readszie];
    fseek(pf, bm.bfOffBits, SEEK_SET);
    fread(pBmpData, 1, readszie, pf);
 
    w = bmx;
    h = bmy;
    pdat = new byte[w * h * 3];
 
    int iy,ix;
    BYTE btPil;
    char caTmp[4];
    DWORD dwDataOff = 0;
    int picy = 0;
    for(int n = 0; n < readtimes; ++n)
    {
        for (iy = 0; iy < readlines; ++iy)
        {
            for (ix = 0; ix < bmx; ++ix)
            {
                if (pRgb == NULL)
                {
                    caTmp[0] = pBmpData[(iy * dwRealWidth + ix * iBitSteps) + 2];
                    caTmp[1] = pBmpData[(iy * dwRealWidth + ix * iBitSteps) + 1];
                    caTmp[2] = pBmpData[(iy * dwRealWidth + ix * iBitSteps)];
                }
                else
                {
                    btPil = pBmpData[(iy * dwRealWidth + ix * iBitSteps)];
                    if (bmif.biClrUsed != 0)
                    {
                        caTmp[0] = pRgb[btPil].rgbRed;
                        caTmp[1] = pRgb[btPil].rgbGreen;
                        caTmp[2] = pRgb[btPil].rgbBlue;
                    }
                    else
                    {
                        caTmp[0] = caTmp[1] = caTmp[2] = btPil;
                    }
 
                }
 
                if (bmif.biHeight < 0)        // 有时bmp图像的高会是负值，这时则不用颠倒 
                {
                    dwDataOff = (iy + picy) * bmx + ix;
                }
                else
                {
                    dwDataOff = (bmy - (iy + picy) - 1) * bmx + ix;
                }
 
                caTmp[3] = 255;
 
                if (bAlpha)
                {
                    caTmp[3] = pBmpData[(iy * dwRealWidth + ix * iBitSteps) + 3];
                }
 
				pdat[dwDataOff*3] = caTmp[0];
				pdat[dwDataOff*3+1] = caTmp[1];
				pdat[dwDataOff*3+2] = caTmp[2];
 
            }
        }
        picy += readlines;
        int realbits = fread(pBmpData, 1, readszie, pf);
        if (realbits < readszie) readlines = realbits / dwRealWidth;
    }
 
    if (pf)
        fclose(pf);
    pf = NULL;

	delete pBmpData;
	delete pRgb;

	return pdat;
}

int LoadBMP3 (const char* szFile, BYTE** ppbBits, BYTE** ppbPalette, int &w, int &h)
{
	int i, rc = 0;
	FILE *pfile = NULL;
	BITMAPFILEHEADER bmfh;
	BITMAPINFOHEADER bmih;
	RGBQUAD rgrgbPalette[256];
	ULONG cbBmpBits;
	BYTE* pbBmpBits;
	byte  *pb, *pbPal = NULL;
	ULONG cbPalBytes;
	ULONG biTrueWidth;

	// Bogus parameter check
	if (!(ppbPalette != NULL && ppbBits != NULL))
		{ fprintf(stderr, "invalid BMP file\n"); rc = -1000; goto GetOut; }

	// File exists?
	if ((pfile = fopen(szFile, "rb")) == NULL)
		{ fprintf(stderr, "unable to open BMP file\n"); rc = -1; goto GetOut; }
	
	// Read file header
	if (fread(&bmfh, sizeof bmfh, 1/*count*/, pfile) != 1)
		{ rc = -2; goto GetOut; }

	// Bogus file header check
	if (!(bmfh.bfReserved1 == 0 && bmfh.bfReserved2 == 0))
		{ rc = -2000; goto GetOut; }

	// Read info header
	if (fread(&bmih, sizeof bmih, 1/*count*/, pfile) != 1)
		{ rc = -3; goto GetOut; }

	// Bogus info header check
	if (!(bmih.biSize == sizeof bmih && bmih.biPlanes == 1))
		{ fprintf(stderr, "invalid BMP file header\n");  rc = -3000; goto GetOut; }

	// Bogus bit depth?  Only 8-bit supported.
	if (bmih.biBitCount != 8)
		{ fprintf(stderr, "BMP file not 8 bit\n");  rc = -4; goto GetOut; }
	
	// Bogus compression?  Only non-compressed supported.
	if (bmih.biCompression != BI_RGB)
		{ fprintf(stderr, "invalid BMP compression type\n"); rc = -5; goto GetOut; }

	// Figure out how many entires are actually in the table
	if (bmih.biClrUsed == 0)
		{
		bmih.biClrUsed = 256;
		cbPalBytes = (1 << bmih.biBitCount) * sizeof( RGBQUAD );
		}
	else 
		{
		cbPalBytes = bmih.biClrUsed * sizeof( RGBQUAD );
		}

	// Read palette (bmih.biClrUsed entries)
	if (fread(rgrgbPalette, cbPalBytes, 1/*count*/, pfile) != 1)
		{ rc = -6; goto GetOut; }

	// convert to a packed 768 byte palette
	pbPal = (byte *)malloc(768);
	if (pbPal == NULL)
		{ rc = -7; goto GetOut; }

	pb = pbPal;

	// Copy over used entries
	for (i = 0; i < (int)bmih.biClrUsed; i++)
	{
		*pb++ = rgrgbPalette[i].rgbRed;
		*pb++ = rgrgbPalette[i].rgbGreen;
		*pb++ = rgrgbPalette[i].rgbBlue;
	}

	// Fill in unused entires will 0,0,0
	for (i = bmih.biClrUsed; i < 256; i++) 
	{
		*pb++ = 0;
		*pb++ = 0;
		*pb++ = 0;
	}

	// Read bitmap bits (remainder of file)
	cbBmpBits = bmfh.bfSize - ftell(pfile);
	pb = (byte *)malloc(cbBmpBits);
	if (fread(pb, cbBmpBits, 1/*count*/, pfile) != 1)
		{ rc = -7; goto GetOut; }

	pbBmpBits = (byte *)malloc(cbBmpBits);

	// data is actually stored with the width being rounded up to a multiple of 4
	biTrueWidth = (bmih.biWidth + 3) & ~3;
	
	// reverse the order of the data.
	pb += (bmih.biHeight - 1) * biTrueWidth;
	for(i = 0; i < bmih.biHeight; i++)
	{
		memmove(&pbBmpBits[biTrueWidth * i], pb, biTrueWidth);
		pb -= biTrueWidth;
	}

	pb += biTrueWidth;
	free(pb);

	/*bmhd.*/w = (WORD)bmih.biWidth;
	/*bmhd.*/h = (WORD)bmih.biHeight;
	// Set output parameters
	*ppbPalette = pbPal;
	*ppbBits = pbBmpBits;

GetOut:
	if (pfile) 
		fclose(pfile);

	return rc;
}