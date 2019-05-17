#include "CVector3D.h"

void CVector3D::SetCVector3D(double x, double y, double z)
{
	this->x = (float)x;
	this->y = (float)y;
	this->z = (float)z;
}
double CVector3D::Dot(const CVector3D& v)
{
	double ret = x * v.x + y * v.y + z * v.z;
	return ret;
}
double CVector3D::Mod()
{
	double ret = sqrt(x * x + y * y + z * z);
	return ret;
}
double CVector3D::GetAngle(CVector3D& v)
{
	double mod1, mod2;
	mod1 = this->Mod();
	mod2 = v.Mod();
	double ret;
	if (mod1 == 0 || mod2 == 0)
	{
		return 0;
	}
	else
	{
		double cos_ret = this->Dot(v) / mod1 / mod2;
		ret = acos(cos_ret);
	}
	return ret;
}

CVector3D CVector3D::UnitVictor()//求单位向量
{
	double mod = Mod();
	CVector3D Unit;//默认[0,0]
	if (mod != 0)
	{
		Unit.SetCVector3D(x / mod, y / mod, z / mod);
	}
	return Unit;
}

CVector3D& CVector3D::normalized()
{
	float mod = (float)this->Mod();
	if (ISFLOATZERO(mod))
	{
		x = y = 0;
		return *this;
	}
	x /= mod;
	y /= mod;
	z /= mod;
	return *this;
}

CVector3D CVector3D::normalize()
{
	float mod = (float)this->Mod();
	if (ISFLOATZERO(mod))
	{
		x = y = 0;
		return *this;
	}
	CVector3D New(x / mod, y / mod, z / mod);
	return New;
}

CVector3D  CVector3D::operator+(const CVector3D& v)
{
	CVector3D New(x + v.x, y + v.y, z + v.z);
	return New;
}
CVector3D  CVector3D::operator-(const CVector3D& v)
{
	CVector3D New(x - v.x, y - v.y, z - v.z);
	return New;
}
CVector3D  CVector3D::operator*(const CVector3D& v)
{
	CVector3D New(x * v.x, y * v.y, z * v.z);
	return New;
}
CVector3D  CVector3D::operator/(const CVector3D& v)
{
	CVector3D New(x / v.x, y / v.y, z / v.z);
	return New;
}

CVector3D  CVector3D::operator+=(const CVector3D& v)
{
	x += v.x;
	y += v.y;
	z += v.z;
	return *this;
}
CVector3D  CVector3D::operator-=(const CVector3D& v)
{
	x -= v.x;
	y -= v.y;
	z -= v.z;
	return *this;
}
CVector3D  CVector3D::operator*=(const CVector3D& v)
{
	x *= v.x;
	y *= v.y;
	z *= v.z;
	return *this;
}
CVector3D&  CVector3D::operator/=(const CVector3D& v)
{
	x /= v.x;
	y /= v.y;
	z /= v.z;
	return *this;
}


CVector3D  CVector3D::operator+(double v)
{
	CVector3D New(x + (float)v, y + (float)v, z + (float)v);
	return New;
}
CVector3D  CVector3D::operator-(double v)
{
	CVector3D New(x - (float)v, y - (float)v, z - (float)v);
	return New;
}
CVector3D  CVector3D::operator*(double v)
{
	CVector3D New(x * (float)v, y * (float)v, z * (float)v);
	return New;
}
CVector3D  CVector3D::operator/(double v)
{
	CVector3D New(x / (float)v, y / (float)v, z / (float)v);
	return New;
}

CVector3D  CVector3D::operator+=(double v)
{
	this->SetCVector3D(x + (float)v, y + (float)v, z + (float)v);
	return *this;
}
CVector3D  CVector3D::operator-=(double v)
{
	this->SetCVector3D(x - (float)v, y - (float)v, z - (float)v);
	return *this;
}
CVector3D  CVector3D::operator*=(double v)
{
	this->SetCVector3D(x * (float)v, y * (float)v, z * (float)v);
	return *this;
}
CVector3D&  CVector3D::operator/=(double v)
{
	this->SetCVector3D(x / (float)v, y / (float)v, z / (float)v);
	return *this;
}
CVector3D  CVector3D::operator=(const CVector3D& v)
{
	x = v.x;
	y = v.y;
	z = v.z;
	return *this;
}
CVector3D  CVector3D::operator=(double v)
{
	CVector3D New((float)v, (float)v, (float)v);
	return New;
}


CVector3D CVector3D::Cross(const CVector3D& v)
{
	CVector3D t;
	t.x = y * v.z - v.y*z;
	t.y = z * v.x - v.z*x;
	t.z = x * v.y - y * v.x;
	return t;
}