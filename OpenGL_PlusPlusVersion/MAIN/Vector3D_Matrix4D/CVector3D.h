#ifndef __CVECTOR_3D_H__
#define __CVECTOR_3D_H__
#include <math.h>
#include <cmath>
#define PI 3.14159265358979323846
//1e-5//科学计数法 1*10^(-5) 0.00001
#define ISFLOATZERO(x)	abs(x)<1e-5
class CVector3D
{
public:
	float x, y, z;
	CVector3D() {}
	CVector3D(float _x, float _y, float _z) :x(_x), y(_y), z(_z) {}

	void SetCVector3D(double x, double y, double z);
	double Dot(const CVector3D& v);//求点积
	double Mod();//求模
	double GetAngle(CVector3D& v);//求夹角
	CVector3D UnitVictor();//求单位向量
	CVector3D normalize();
	CVector3D& normalized();

	CVector3D  operator+(const CVector3D& v); //重载+运算符函数
	CVector3D  operator-(const CVector3D& v); //重载-运算符函数
	CVector3D  operator*(const CVector3D& v); //重载*运算符函数
	CVector3D  operator/(const CVector3D& v); //重载/运算符函数

	CVector3D  operator+=(const CVector3D& v); //重载+=运算符函数
	CVector3D  operator-=(const CVector3D& v); //重载-=运算符函数
	CVector3D  operator*=(const CVector3D& v); //重载*=运算符函数
	CVector3D&  operator/=(const CVector3D& v); //重载/=运算符函数

	CVector3D  operator+(double v);
	CVector3D  operator-(double v);
	CVector3D  operator*(double v);
	CVector3D  operator/(double v);

	CVector3D  operator+=(double v);
	CVector3D  operator-=(double v);
	CVector3D  operator*=(double v);
	CVector3D&  operator/=(double v);

	CVector3D  operator=(const CVector3D& v);
	CVector3D  operator=(double v);

	CVector3D Cross(const CVector3D& v);//3维向量叉乘

};
#endif