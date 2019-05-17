#include "BITMAP.h"

Sprite::Sprite()
{
	Sprite::InitSpriteInfoData();
}

Sprite::Sprite(const char *FileName)
{
	Sprite::InitSpriteInfoData();

	this->Create(FileName);
}

void *Sprite::Create(const char *FileName)
{
	m_BitMapRGBData = ATENGINE->LoadBitMapRGBData(FileName);
	memcpy_s(m_bf, sizeof(BITMAPFILEHEADER), &ATENGINE->m_bf, sizeof(ATENGINE->m_bf));
	memcpy_s(m_bi, sizeof(BITMAPINFOHEADER), &ATENGINE->m_bi, sizeof(ATENGINE->m_bi));
	return m_BitMapRGBData;
}
void Sprite::SetSpriteScale(float X, float Y)
{
	m_Scale->Set_X(X);
	m_Scale->Set_Y(Y);
}
void Sprite::SetSpritePosition(float X, float Y)
{
	m_Position->Set_X(X);
	m_Position->Set_Y(Y);
}
LPPIXCOLOR *Sprite::GetBitMapRGBData()
{
	return *m_BitMapRGBData;
}
void Sprite::DrawSprite()
{
	if (m_SpriteState == 0)
	{
		//不受矩阵影响
		//更改绘制颜色的起始位置
		//glRasterPos2f(m_Position->Get_X(), m_Position->Get_Y());
		//glPixelZoom(m_Scale->Get_X(), m_Scale->Get_Y());
		//glDrawPixels(
		//	m_bi->biWidth, m_bi->biHeight,
		//	GL_BGR_EXT, GL_UNSIGNED_BYTE,
		//	*m_BitMapRGBData);
		ATENGINE->DrawRGB_DATA(*m_Position, *m_Scale,ATATCONTENTSIZE(m_bi->biWidth, m_bi->biHeight), GL_BGR_EXT, GL_UNSIGNED_BYTE, *m_BitMapRGBData);
	}
}
void Sprite::DrawSprite(float Width, float Height)
{
	m_Scale->Set_X(Width / m_bi->biWidth);
	m_Scale->Set_Y(Height / m_bi->biHeight);
	Sprite::DrawSprite();
}
//void Sprite::DeleteSprite()
//{
//	m_SpriteState = -1;
//}

Sprite::~Sprite()
{
	Sprite::DeleteSpriteInfoData();
}
void Sprite::InitSpriteInfoData()
{
	m_Position = new ATATPOS2D();
	m_Scale = new ATATSCALE2D();
	m_bf = new BITMAPFILEHEADER();
	m_bi = new BITMAPINFOHEADER();
	m_Position->Set_X(0.0f);
	m_Position->Set_Y(0.0f);
	m_Scale->Set_X(1.0f);
	m_Scale->Set_Y(1.0f);
	m_SpriteState = 0;
}
void Sprite::DeleteSpriteInfoData()
{
	delete m_Position;
	delete m_Scale;
	delete m_bf;
	delete m_bi;
	m_Position = NULL;
	m_Scale = NULL;
	m_bf = NULL;
	m_bi = NULL;
	m_SpriteState = 0;
}
