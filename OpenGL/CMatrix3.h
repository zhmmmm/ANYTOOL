#ifndef __CMATRIX3_H__
#define __CMATRIX3_H__
#include "CVerctor2D.h"
#include <Windows.h>

//3x3¾ØÕó
union Mat3 
{
	struct{
		float _11,_12,_13;
		float _21,_22,_23;
		float _31,_32,_33;
	};
	float m[3][3];
};

class CMatrix3
{
public:
	Mat3 M3;
	CMatrix3()
	{
		Identity();
	}
	//µ¥Î»»¯¾ØÕó
	CMatrix3& Identity()
	{
		M3._11=1,M3._12=0,M3._13=0;
		M3._21=0,M3._22=1,M3._23=0;
		M3._31=0,M3._32=0,M3._33=1;
		return *this;
	}
	//Æ½ÒÆ¾ØÕó
	CMatrix3& Translate(float x,float y)
	{
		CMatrix3 tmp;
		tmp.M3._31 = x;
		tmp.M3._32 = y;
		*this = (*this)*tmp;
		return *this;
	}
	
	CMatrix3 SetTranslate(float x,float y)
	{
		M3._31=x;
		M3._32=y;
		return *this;
	}
	//Ëõ·Å¾ØÕó
	CMatrix3& Scale(float x,float y)
	{
		CMatrix3 tmp;
		tmp.M3._11=x;
		tmp.M3._22=y;
		*this = (*this)*tmp;
		return *this;
	}
	CMatrix3 SetScale(float x,float y)
	{
		M3._11=x;
		M3._22=y;
		return *this;
	}
	//Ðý×ª¾ØÕó(»¡¶È)
	CMatrix3& Rotate_r(float angle_r)
	{
		CMatrix3 tmp;
		tmp.M3._11=cos(angle_r);
		tmp.M3._12=sin(angle_r);
		tmp.M3._21=-tmp.M3._12;
		tmp.M3._22=tmp.M3._11;
		*this = (*this)*tmp;
		return *this;
	}
	CMatrix3 SetRotate_r(float angle_r)
	{
		M3._11=cos(angle_r);
		M3._12=sin(angle_r);
		M3._21=-M3._12;
		M3._22=M3._11;
		return *this;
	}
	//Ðý×ª¾ØÕó(½Ç¶È)
	CMatrix3& Rotate_d(float angle_d)
	{
		return Rotate_r(angle_d/180*M_PI);
	}
	CMatrix3 SetRotate_d(float angle_d)
	{
		return SetRotate_r(angle_d/180*M_PI);
	}
	
	CMatrix3 operator * (CMatrix3& m)
	{
		CMatrix3 n;
		n.M3._11 = M3._11*m.M3._11+   M3._12*m.M3._21+   M3._13*m.M3._31;
		n.M3._12 = M3._11*m.M3._12+   M3._12*m.M3._22+   M3._13*m.M3._32;
		n.M3._13 = M3._11*m.M3._13+   M3._12*m.M3._23+   M3._13*m.M3._33;
		n.M3._21 = M3._21*m.M3._11+   M3._22*m.M3._21+   M3._23*m.M3._31;
		n.M3._22 = M3._21*m.M3._12+   M3._22*m.M3._22+   M3._23*m.M3._32;
		n.M3._23 = M3._21*m.M3._13+   M3._22*m.M3._23+   M3._23*m.M3._33;
		n.M3._31 = M3._31*m.M3._11+   M3._32*m.M3._21+   M3._33*m.M3._31;
		n.M3._32 = M3._31*m.M3._12+   M3._32*m.M3._22+   M3._33*m.M3._32;
		n.M3._33 = M3._31*m.M3._13+   M3._32*m.M3._23+   M3._33*m.M3._33;
		return n;
	}
};

class MyXform:public XFORM
{
public:
	MyXform()
	{
		Identity();
	}
	MyXform(CMatrix3& m)
	{
		eM11=m.M3._11;
		eM12=m.M3._12;
		eM21=m.M3._21;
		eM22=m.M3._22;
		eDx=m.M3._31;
		eDy=m.M3._32;
	}
	MyXform& operator = (CMatrix3& m)
	{
		eM11=m.M3._11;
		eM12=m.M3._12;
		eM21=m.M3._21;
		eM22=m.M3._22;
		eDx=m.M3._31;
		eDy=m.M3._32;
		return *this;
	}
	MyXform Identity()
	{
		eM11=1;
		eM12=0;
		eM21=0;
		eM22=1;
		eDx=0;
		eDy=0;
		return *this;
	}
};



inline CVerctor2D operator * (CVerctor2D& v,CMatrix3& m)
{
	float x=v.m_x*m.M3._11+v.m_y*m.M3._21+m.M3._31;
	float y=v.m_x*m.M3._12+v.m_y*m.M3._22+m.M3._32;
	return CVerctor2D(x,y);
}
#endif