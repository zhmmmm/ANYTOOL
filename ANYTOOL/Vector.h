#pragma once
#include "stdafx.h"
#include <cmath>
#include <cassert>

#define ISFloatZero(x)	abs(x)<=0.00001f
//二维向量类
class Vector2D
{
public:
	float x, y;
public:
	Vector2D() :x(0), y(0) {}
	Vector2D(int n) :x(n), y(n) {}
	Vector2D(float n) :x(n), y(n) {}
	Vector2D(int _x, int _y) :x(float(_x)), y(float(_y)) {}
	Vector2D(float _x, float _y) :x(_x), y(_y) {}
	Vector2D(int _x, float _y) :x(float(_x)), y(_y) {}
	Vector2D(float _x, int _y) :x(_x), y(float(_y)) {}
	//因为成员是纯数值的，没有涉及堆内存，所以可以
	//不写拷贝构造和同类赋值函数，析构同理

	//向量的运算
	//向量的模
	float length()
	{
		return sqrtf(x*x + y * y);
	}
	float lengthSquare()
	{
		return x * x + y * y;
	}
	//向量的单位化
	Vector2D& Normalized()
	{
		float len = sqrtf(x*x + y * y);
		assert(!ISFloatZero(len));
		x /= len;
		y /= len;
		return *this;
	}
	//求一个单位向量
	Vector2D Normalize()
	{
		float len = sqrtf(x*x + y * y);
		assert(!ISFloatZero(len));
		Vector2D temp(x / len, y / len);
		return temp;
	}

	//向量加法
	Vector2D operator + (const Vector2D& t)
	{
		Vector2D temp(x + t.x, y + t.y);
		return temp;
	}
	//+=
	Vector2D& operator += (const Vector2D& t)
	{
		x += t.x;
		y += t.y;
		return *this;
	}
	//-
	Vector2D operator - (const Vector2D& t)
	{
		Vector2D temp(x - t.x, y - t.y);
		return temp;
	}
	//-=
	Vector2D& operator -= (const Vector2D& t)
	{
		x -= t.x;
		y -= t.y;
		return *this;
	}
	//*k(数乘)
	Vector2D operator * (float k) const
	{
		Vector2D temp(x*k, y*k);
		return temp;
	}
	///k(数除)
	Vector2D operator / (float k) const
	{
		assert(!ISFloatZero(k));
		Vector2D temp(x / k, y / k);
		return temp;
	}
	//*=k(数乘)
	Vector2D& operator *= (float k)
	{
		x *= k, y *= k;
		return *this;
	}
	///=k(数除)
	Vector2D& operator /= (float k)
	{
		assert(!ISFloatZero(k));
		x /= k, y /= k;
		return *this;
	}

	//点乘|a|·|b|cos(ab)
	float dot(const Vector2D& t)
	{
		return x * t.x + y * t.y;
	}
	//叉乘|a|·|b|sin(ab)
	float cross(const Vector2D& t)
	{
		return x * t.y - t.x*y;
	}
	//求角度
	float angle_r(const Vector2D& t)
	{
		float len1 = sqrtf(x*x + y * y);//求的模
		float len2 = sqrtf(t.x*t.x + t.y*t.y);//求的模
		len1 *= len2;
		assert(!ISFloatZero(len1));
		float dt = x * t.x + y * t.y;//求的dot	
		float c = dt / len1;//求的余弦值
		float a = acosf(c);//反三角函数求角度
		return a;//弧度值？
	}
	//求投影
	Vector2D project(const Vector2D& t)
	{
		float dt = dot(t);
		float sqt = t.x*t.x + t.y*t.y;
		Vector2D temp = t * dt / sqt;
		return temp;
	}
};

