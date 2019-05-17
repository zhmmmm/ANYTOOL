#pragma once
/*
当前头文件是给引擎用的,不要把其他的头文件包含进来
*/
//第三方库
#include "../../ThirdPartyLibraries/NOTHINGS_STD/stb_image.h"
#include "../../ThirdPartyLibraries/NOTHINGS_STD/stb_image_resize.h"
#include "../../ThirdPartyLibraries/NOTHINGS_STD/stb_image_write.h"



#include "../Object.h"



#define AT_INITOPENGL 0


typedef struct ATRGBA
{
	float R = 0;
	float G = 0;
	float B = 0;
	//透明度
	float Alpha = 1;
}AT_RGBA, *LPAT_RGBA;

typedef struct ATRGB
{
	float R = 0;
	float G = 0;
	float B = 0;
}AT_RGB, *LPAT_RGB;

typedef struct stPixColor
{
	unsigned char B;
	unsigned char G;
	unsigned char R;
}PIXCOLOR, *LPPIXCOLOR;

typedef struct POSITION
{
	float X = 0;
	float Y = 0;
}Position, *LPPosition;

enum MATRIXMODE
{
	LEFTUP,
	RIGHTUP,
	CENTER,
	LEFTDOWN,
	RIGHTDOWN,
	ZERO
};

class ATATRGB
{
public:
	float R = 0;
	float G = 0;
	float B = 0;

	ATATRGB() {}
	ATATRGB(float R, float G, float B)
	{
		this->R = R;
		this->G = G;
		this->B = B;
	}
	ATATRGB(unsigned char R, unsigned char G, unsigned char B)
	{
		this->R = R / 255.0f;
		this->G = G / 255.0f;
		this->B = B / 255.0f;
	}
	ATATRGB(int R, int G, int B)
	{
		this->R = R / 255.0f;
		this->G = G / 255.0f;
		this->B = B / 255.0f;
	}
	float Get_R()
	{
		return this->R;
	}
	float Get_G()
	{
		return this->G;
	}
	float Get_B()
	{
		return this->B;
	}
	void Set_R(float R)
	{
		this->R = R;
	}
	void Set_G(float G)
	{
		this->G = G;
	}
	void Set_B(float B)
	{
		this->B = B;
	}

	static const ATATRGB RED;
	static const ATATRGB YELLOW;
	static const ATATRGB BLUE;
	static const ATATRGB GREEN;
	static const ATATRGB WHITE;
	static const ATATRGB BLACK;
	static const ATATRGB MAGENTA;
	static const ATATRGB ORANGE;
};

class ATATRGBA :public ATATRGB
{
public:
	float A = 1;

	ATATRGBA() {}
	ATATRGBA(float R, float G, float B, float A)
	{
		ATATRGB::Set_R(R);
		ATATRGB::Set_G(G);
		ATATRGB::Set_B(B);

		this->A = A;
	}
	ATATRGBA(unsigned char R, unsigned char G, unsigned char B, unsigned char A)
	{
		ATATRGB::Set_R(R / 255.0f);
		ATATRGB::Set_G(G / 255.0f);
		ATATRGB::Set_B(B / 255.0f);

		this->A = A / 255.0f;
	}
	ATATRGBA(int R, int G, int B, int A)
	{
		ATATRGB::Set_R(R / 255.0f);
		ATATRGB::Set_G(G / 255.0f);
		ATATRGB::Set_B(B / 255.0f);

		this->A = A / 255.0f;
	}
	float Get_A()
	{
		return this->A;
	}
	void Set_A(float A)
	{
		this->A = A;
	}

	static const ATATRGBA RED;
	static const ATATRGBA YELLOW;
	static const ATATRGBA BLUE;
	static const ATATRGBA GREEN;
	static const ATATRGBA WHITE;
	static const ATATRGBA BLACK;
	static const ATATRGBA MAGENTA;
	static const ATATRGBA ORANGE;
};

class ATATPOS2D
{
public:
	float X = 0;
	float Y = 0;

	ATATPOS2D() {}
	ATATPOS2D(float X, float Y)
	{
		this->X = X;
		this->Y = Y;
	}
	ATATPOS2D(int X, int Y)
	{
		this->X = X * 1.0f;
		this->Y = Y * 1.0f;
	}
	float Get_X()
	{
		return this->X;
	}
	float Get_Y()
	{
		return this->Y;
	}
	void Set_X(float X)
	{
		this->X = X;
	}
	void Set_Y(float Y)
	{
		this->Y = Y;
	}

	static const ATATPOS2D ZERO;
};

class ATATPOS3D :public ATATPOS2D
{
public:
	float Z = 0;

	ATATPOS3D() {}
	ATATPOS3D(float X, float Y, float Z)
	{
		ATATPOS2D::Set_X(X);
		ATATPOS2D::Set_Y(Y);
		this->Z = Z;
	}
	ATATPOS3D(int X, int Y, int Z)
	{
		ATATPOS2D::Set_X(X * 1.0f);
		ATATPOS2D::Set_Y(Y * 1.0f);
		this->Z = Z * 1.0f;
	}
	float Get_Z()
	{
		return this->Z;
	}
	void Set_Z(float Z)
	{
		this->Z = Z;
	}

	static const ATATPOS3D ZERO;
};

class ATATSCALE2D
{
public:
	float X = 0;
	float Y = 0;

	ATATSCALE2D() {}
	ATATSCALE2D(float X, float Y)
	{
		this->X = X;
		this->Y = Y;
	}
	ATATSCALE2D(int X, int Y)
	{
		this->X = X * 1.0f;
		this->Y = Y * 1.0f;
	}
	float Get_X()
	{
		return this->X;
	}
	float Get_Y()
	{
		return this->Y;
	}
	void Set_X(float X)
	{
		this->X = X;
	}
	void Set_Y(float Y)
	{
		this->Y = Y;
	}

	static const ATATSCALE2D ZERO;
};

class ATATCONTENTSIZE
{

public:
	float Width = 0;
	float Height = 0;

	ATATCONTENTSIZE() {}
	ATATCONTENTSIZE(float Width, float Height)
	{
		this->Width = Width;
		this->Height = Height;
	}
	ATATCONTENTSIZE(int Width, int Height)
	{
		this->Width = (float)Width;
		this->Height = (float)Height;
	}
	float Get_Width()
	{
		return this->Width;
	}
	float Get_Height()
	{
		return this->Height;
	}
	void Set_Width(float Width)
	{
		this->Width = Width;
	}
	void Set_Height(float Height)
	{
		this->Height = Height;
	}
};