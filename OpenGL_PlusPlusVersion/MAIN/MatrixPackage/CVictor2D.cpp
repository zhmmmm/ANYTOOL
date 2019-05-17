#include "CVictor2D.h"
CVictor2D::CVictor2D()
{
	m_X=0;
	m_Y=0;
}
CVictor2D::CVictor2D(double x,double y)
{
	m_X=x;
	m_Y=y;
}
CVictor2D::CVictor2D(const CVictor2D& old)
{
	m_X=old.m_X;
	m_Y=old.m_Y;
}
void CVictor2D::SetVictor(double x,double y)
{
	m_X=x;
	m_Y=y;
}
double CVictor2D::GetX()
{
	return m_X;
}
double CVictor2D::GetY()
{
	return m_Y;
}
double CVictor2D::Dot(const CVictor2D& v)//求点积
{
	double ret=m_X*v.m_X+m_Y*v.m_Y;
	return ret;
}
double CVictor2D::Mod()//求模
{
	double ret=sqrt(m_X*m_X+m_Y*m_Y);
	return ret;
}
CVictor2D CVictor2D::GetShadow(const CVictor2D& cvct2d)//当前对象在cvct2D上的投影
{
	double k=this->Dot(cvct2d)/(cvct2d.m_X*cvct2d.m_X+cvct2d.m_Y*cvct2d.m_Y);
	CVictor2D shadow(m_X*k,m_Y*k);
	return shadow;
}
CVictor2D CVictor2D::UnitVictor()//求单位向量
{
	double mod=Mod();
	CVictor2D Unit;//默认[0,0]
	if (mod!=0)
	{
		Unit.SetVictor(m_X/mod,m_Y/mod);
	}
	return Unit;
}
double CVictor2D::GetAngle(CVictor2D& cvct2d)//求夹角
{
	double mod1,mod2;
	mod1=this->Mod();
	mod2=cvct2d.Mod();
	double ret;
	if (mod1==0||mod2==0)
	{
		return 0;
	}else
	{
		double cos_ret=this->Dot(cvct2d)/mod1/mod2;
		ret=acos(cos_ret);
	}
	return ret;
}
CVictor2D  CVictor2D::operator+(const CVictor2D& cvct2d) //重载+运算符函数
{
	CVictor2D New(m_X+cvct2d.m_X,m_Y+cvct2d.m_Y);
	return New;
}
CVictor2D&  CVictor2D::operator+=(const CVictor2D& cvct2d)//重载+=运算符函数
{
	m_X+=cvct2d.m_X;
	m_Y+=cvct2d.m_Y;
	return *this;
}
CVictor2D  CVictor2D::operator-(const CVictor2D& cvct2d) //重载-运算符函数
{
	CVictor2D New(m_X-cvct2d.m_X,m_Y-cvct2d.m_Y);
	return New;
}
CVictor2D&  CVictor2D::operator-=(const CVictor2D& cvct2d) //重载-=运算符函数
{
	m_X-=cvct2d.m_X;
	m_Y-=cvct2d.m_Y;
	return *this;
}
CVictor2D  CVictor2D::operator*(double k)//数乘重载
{
	CVictor2D New(m_X*k,m_Y*k);
	return New;
}
CVictor2D&  CVictor2D::operator*=(double k)//数乘重载
{
	this->SetVictor(m_X*k,m_Y*k);
	return *this;
}
double  CVictor2D::operator*(const CVictor2D& cvct2d)//求外积,这里2D，返回结果的模
{
	/*double mod1,mod2,angle,ret;
	mod1=Mod();
	mod2=_Mod(cvct2d.m_X,cvct2d.m_Y);
	angle=GetAngle(cvct2d);
	ret=mod1*mod2*sin(angle);
	return ret;*/
	double ret=m_X*cvct2d.m_Y-m_Y*cvct2d.m_X;
	return fabs(ret);
}