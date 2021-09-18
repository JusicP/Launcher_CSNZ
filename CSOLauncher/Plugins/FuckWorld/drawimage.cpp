#include "base.h"

DrawImageItem g_rgDrawImage[MAX_DRAWIMAGE];

void DrawImageInitialize(void)
{
	memset(g_rgDrawImage, 0, sizeof(g_rgDrawImage));
}

void DrawImageAdd(DrawImageItem rgTempDrawImage)
{
	if (rgTempDrawImage.iChanne <= 0 || rgTempDrawImage.iChanne >= MAX_DRAWIMAGE)
	{
		for (int i = 0; i < MAX_DRAWIMAGE; i++)
		{
			if (!g_rgDrawImage[i].flEndDisplayTime)
			{
				g_rgDrawImage[i] = rgTempDrawImage;
				break;
			}
		}
	}
	else
		g_rgDrawImage[rgTempDrawImage.iChanne] = rgTempDrawImage;
}

void DrawImageRedraw()
{
	for (int i = 0; i < MAX_DRAWIMAGE; i++)
	{
		if (!g_rgDrawImage[i].flEndDisplayTime)
			continue;

		if (g_flTime >= g_rgDrawImage[i].flEndDisplayTime)
		{
			g_rgDrawImage[i].flEndDisplayTime = 0.0;
			continue;
		}

		int r, g, b, a;
		r = g_rgDrawImage[i].color.r;
		g = g_rgDrawImage[i].color.g;
		b = g_rgDrawImage[i].color.b;

		switch (g_rgDrawImage[i].iMode)
		{
			case 1:
			{
				float flHasDisplayTime = g_flTime - g_rgDrawImage[i].flStartDisplayTime;
				float flNeedDisplayTime = g_rgDrawImage[i].flEndDisplayTime - g_rgDrawImage[i].flStartDisplayTime;
				a = int(flHasDisplayTime / flNeedDisplayTime * 255);
				ScaleColors(r, g, b, a);
				break;
			}
			case 2:
			{
				float flHasDisplayTime = g_flTime - g_rgDrawImage[i].flStartDisplayTime;
				float flNeedDisplayTime = g_rgDrawImage[i].flEndDisplayTime - g_rgDrawImage[i].flStartDisplayTime;
				a = 255 - int(flHasDisplayTime / flNeedDisplayTime * 255);
				ScaleColors(r, g, b, a);
				break;
			}
			case 3:
			{
				float flHasDisplayTime = g_flTime - g_rgDrawImage[i].flStartDisplayTime;
				float flNeedDisplayTime = g_rgDrawImage[i].flEndDisplayTime - g_rgDrawImage[i].flStartDisplayTime;
				a = int(flHasDisplayTime / flNeedDisplayTime * 510);
				if (a > 255)
					a = 255 - (a - 255);
				ScaleColors(r, g, b, a);
				break;
			}
		}
		
		if(g_rgDrawImage[i].iCheck>0)
		{
			g_rgDrawImage[i].hl_hSprites = GetSprite(g_rgDrawImage[i].iSprIndex);
		}
		gEngfuncs.pfnSPR_Set(g_rgDrawImage[i].hl_hSprites, r, g, b);
		
		if (!g_rgDrawImage[i].iCenter)
		{
			switch (g_rgDrawImage[i].iFunction)
			{
				case 0:
				{
					if(g_rgDrawImage[i].iCheck>0)
					{
						if(g_rgDrawImage[i].iLength>-1)
						{
							wrect_t *TempRect;
							TempRect = &GetSpriteRect(g_rgDrawImage[i].iSprIndex);
							TempRect->right = g_rgDrawImage[i].iLength;
							gEngfuncs.pfnSPR_Draw(0, g_rgDrawImage[i].x, g_rgDrawImage[i].y,TempRect);
						}
						else
						{
							gEngfuncs.pfnSPR_Draw(0, g_rgDrawImage[i].x, g_rgDrawImage[i].y,&GetSpriteRect(g_rgDrawImage[i].iSprIndex));
						}
					}
					else
					{
						gEngfuncs.pfnSPR_Draw(0, g_rgDrawImage[i].x, g_rgDrawImage[i].y, NULL);
					}
					break;
				}
				case 1:
				{
					if(g_rgDrawImage[i].iCheck>0)
					{
						if(g_rgDrawImage[i].iLength>-1)
						{
							wrect_t *TempRect;
							TempRect = &GetSpriteRect(g_rgDrawImage[i].iSprIndex);
							TempRect->right = g_rgDrawImage[i].iLength;
							gEngfuncs.pfnSPR_DrawAdditive(0, g_rgDrawImage[i].x, g_rgDrawImage[i].y, TempRect);
						}
						else
						{
							gEngfuncs.pfnSPR_DrawAdditive(0, g_rgDrawImage[i].x, g_rgDrawImage[i].y, &GetSpriteRect(g_rgDrawImage[i].iSprIndex));
						}
					}
					else
					{
						gEngfuncs.pfnSPR_DrawAdditive(0, g_rgDrawImage[i].x, g_rgDrawImage[i].y, NULL);
					}
					break;
				}
				case 2:
				{
					if(g_rgDrawImage[i].iCheck>0)
					{
						if(g_rgDrawImage[i].iLength>-1)
						{
							wrect_t *TempRect;
							TempRect = &GetSpriteRect(g_rgDrawImage[i].iSprIndex);
							TempRect->right = g_rgDrawImage[i].iLength;
							gEngfuncs.pfnSPR_DrawHoles(0, g_rgDrawImage[i].x, g_rgDrawImage[i].y, TempRect);
						}
						else
						{
							gEngfuncs.pfnSPR_DrawHoles(0, g_rgDrawImage[i].x, g_rgDrawImage[i].y, &GetSpriteRect(g_rgDrawImage[i].iSprIndex));
						}
					}
					else
					{
						gEngfuncs.pfnSPR_DrawHoles(0, g_rgDrawImage[i].x, g_rgDrawImage[i].y, NULL);
					}
					break;
				}
			}
		}
		else
		{
			switch (g_rgDrawImage[i].iFunction)
			{
				case 0:
				{
					if(g_rgDrawImage[i].iCheck>0)
					{
						if(g_rgDrawImage[i].iLength>-1)
						{
							wrect_t *TempRect;
							TempRect = &GetSpriteRect(g_rgDrawImage[i].iSprIndex);
							TempRect->right = g_rgDrawImage[i].iLength;
							gEngfuncs.pfnSPR_Draw(0, g_rgDrawImage[i].x - gEngfuncs.pfnSPR_Width(g_rgDrawImage[i].hl_hSprites, 0) / 2, g_rgDrawImage[i].y - gEngfuncs.pfnSPR_Height(g_rgDrawImage[i].hl_hSprites, 0) / 2, TempRect);
						}
						else
						{
							gEngfuncs.pfnSPR_Draw(0, g_rgDrawImage[i].x - gEngfuncs.pfnSPR_Width(g_rgDrawImage[i].hl_hSprites, 0) / 2, g_rgDrawImage[i].y - gEngfuncs.pfnSPR_Height(g_rgDrawImage[i].hl_hSprites, 0) / 2, &GetSpriteRect(g_rgDrawImage[i].iSprIndex));
						}
					}
					else
					{
						gEngfuncs.pfnSPR_Draw(0, g_rgDrawImage[i].x - gEngfuncs.pfnSPR_Width(g_rgDrawImage[i].hl_hSprites, 0) / 2, g_rgDrawImage[i].y - gEngfuncs.pfnSPR_Height(g_rgDrawImage[i].hl_hSprites, 0) / 2, NULL);
					}
					break;
				}
				case 1:
				{
					if(g_rgDrawImage[i].iCheck>0)
					{
						if(g_rgDrawImage[i].iLength>-1)
						{
							wrect_t *TempRect;
							TempRect = &GetSpriteRect(g_rgDrawImage[i].iSprIndex);
							TempRect->right = g_rgDrawImage[i].iLength;
							gEngfuncs.pfnSPR_DrawAdditive(0, g_rgDrawImage[i].x - gEngfuncs.pfnSPR_Width(g_rgDrawImage[i].hl_hSprites, 0) / 2, g_rgDrawImage[i].y - gEngfuncs.pfnSPR_Height(g_rgDrawImage[i].hl_hSprites, 0) / 2, TempRect);
						}
						else
						{
							gEngfuncs.pfnSPR_DrawAdditive(0, g_rgDrawImage[i].x - gEngfuncs.pfnSPR_Width(g_rgDrawImage[i].hl_hSprites, 0) / 2, g_rgDrawImage[i].y - gEngfuncs.pfnSPR_Height(g_rgDrawImage[i].hl_hSprites, 0) / 2, &GetSpriteRect(g_rgDrawImage[i].iSprIndex));
						}
					}
					else
					{
						gEngfuncs.pfnSPR_DrawAdditive(0, g_rgDrawImage[i].x - gEngfuncs.pfnSPR_Width(g_rgDrawImage[i].hl_hSprites, 0) / 2, g_rgDrawImage[i].y - gEngfuncs.pfnSPR_Height(g_rgDrawImage[i].hl_hSprites, 0) / 2, NULL);
					}
					break;
				}
				case 2:
				{
					if(g_rgDrawImage[i].iCheck>0)
					{
						if(g_rgDrawImage[i].iLength>-1)
						{
							wrect_t *TempRect;
							TempRect = &GetSpriteRect(g_rgDrawImage[i].iSprIndex);
							TempRect->right = g_rgDrawImage[i].iLength;
							gEngfuncs.pfnSPR_DrawHoles(0, g_rgDrawImage[i].x - gEngfuncs.pfnSPR_Width(g_rgDrawImage[i].hl_hSprites, 0) / 2, g_rgDrawImage[i].y - gEngfuncs.pfnSPR_Height(g_rgDrawImage[i].hl_hSprites, 0) / 2, TempRect);
						}
						else
						{
							gEngfuncs.pfnSPR_DrawHoles(0, g_rgDrawImage[i].x - gEngfuncs.pfnSPR_Width(g_rgDrawImage[i].hl_hSprites, 0) / 2, g_rgDrawImage[i].y - gEngfuncs.pfnSPR_Height(g_rgDrawImage[i].hl_hSprites, 0) / 2, &GetSpriteRect(g_rgDrawImage[i].iSprIndex));
						}
					}
					else
					{
						gEngfuncs.pfnSPR_DrawHoles(0, g_rgDrawImage[i].x - gEngfuncs.pfnSPR_Width(g_rgDrawImage[i].hl_hSprites, 0) / 2, g_rgDrawImage[i].y - gEngfuncs.pfnSPR_Height(g_rgDrawImage[i].hl_hSprites, 0) / 2, NULL);
					}
					break;
				}
			}
		}
	}
}