#ifndef _CVICTOR2D_H_
#define _CVICTOR2D_H_
#include <math.h>
#include <cmath>
#define PI 3.14159265358979323846
class CVictor2D
{
public:
	CVictor2D();
	CVictor2D(double x,double y);
	CVictor2D(const CVictor2D& old);

	void SetVictor(double x,double y);
	double GetX();
	double GetY();
	double Dot(const CVictor2D& cvct2d);//求点积
	double Mod();//求模
	double GetAngle(CVictor2D& cvct2d);//求夹角

	CVictor2D UnitVictor();//求单位向量
	CVictor2D GetShadow(const CVictor2D& cvct2d);
	CVictor2D  operator+(const CVictor2D& cvct2d); //重载+运算符函数
	CVictor2D&  operator+=(const CVictor2D& cvct2d);//重载+=运算符函数
	CVictor2D  operator-(const CVictor2D& cvct2d); //重载-运算符函数
	CVictor2D&  operator-=(const CVictor2D& cvct2d); //重载-=运算符函数
	CVictor2D  operator*(double);//数乘重载
	CVictor2D&  operator*=(double);//数乘重载
	double  operator*(const CVictor2D& cvct2d);//求外积,这里2D，返回结果的模

protected:
private:
	double m_X;
	double m_Y;
};
#endif