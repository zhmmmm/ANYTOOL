#pragma once
#include "OpenGL_AY_Engine.h"

class Sprite
{
	LPPIXCOLOR **m_BitMapRGBData = NULL;
	BITMAPFILEHEADER *m_bf = NULL;
	BITMAPINFOHEADER *m_bi = NULL;
	ATATPOS2D *m_Position = NULL;
	ATATSCALE2D *m_Scale = NULL;

	int m_SpriteState = 0;
public:
	Sprite();
	Sprite(const char *FileName);
	void *Create(const char *FileName);

	void SetSpriteScale(float X, float Y);
	//::::::::::::::::::::::::不建议用:::::::::::::::::::::::::::::::: 如果绘制的开始位置超出视口,那么是绘制不出来的
	void SetSpritePosition(float X, float Y);
	//float GetSpriteWidthAndHeight();

	LPPIXCOLOR *GetBitMapRGBData();

	void DrawSprite();
	//::::::::::::::::::::::::如果调用:::::::::::::::::::::::::::::::: void SetSpriteScale(float X, float Y); 函数是无效的
	void DrawSprite(float Width,float Height);
	//void DeleteSprite();
	~Sprite();
private:
	void InitSpriteInfoData();
	void DeleteSpriteInfoData();
};