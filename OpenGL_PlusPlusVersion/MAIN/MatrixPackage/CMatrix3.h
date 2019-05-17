//3阶方阵
#ifndef _CMATRIX3_H_
#define _CMATRIX3_H_
#include <iostream>
using namespace std;
#include <math.h>
#include "CVictor2D.h"
typedef struct _CMATRIX3 {//3阶方阵结构体
	union {
		struct {
			double        _11, _12, _13;
			double        _21, _22, _23;
			double        _31, _32, _33;
		};
		double m[3][3];
	};
}CMATRIX3D,*LPCMATRIX3D;

class CMatrix3
{
public:
	//==================================方法=========================
	CMatrix3();
	CMatrix3(const CMatrix3& old);
	CMatrix3(double _11,double _12,double _13,double _21,double _22,double _23,double _31,double _32,double _33);
	CMatrix3(double m[3][3]);
	CMatrix3(double** m);

	double GetDet();
	CMatrix3 Transpose();//求转置矩阵
	CMatrix3 Adjoint();//求伴随矩阵
	CMatrix3 Inverse(bool &IsInverse);//求逆矩阵//传入一个逻辑引用参数，来判断是否可逆
	static CMatrix3 GetScaleMtr(double x_ratio,double y_ratio);//比例变换矩阵
	static CMatrix3 GetEqlScaleMtr(double s_ratio);//等比例变换矩阵
	static CMatrix3 GetRotateMtr(double angle);//旋转矩阵
	static CMatrix3 GetTranslationMtr(double x_m,double y_n);//平移
	static CMatrix3 GetX_Symmetry();//X对称变换
	static CMatrix3 GetY_Symmetry();//Y对称变换
	static CMatrix3 GetO_Symmetry();//原点对称变换
	static CMatrix3 Get45_Symmetry();//+45°对称变换
	static CMatrix3 Get_45_Symmetry();//-45°对称变换
	static CMatrix3 Get_Angle_Symmetry(double angle);//关于过原点任意角度直线的对称变换
	static CMatrix3 GetX_TiltMtr(double angle);//X错切变换
	static CMatrix3 GetY_TiltMtr(double angle);//Y错切变换
	CMatrix3 operator + (const CMatrix3& other);
	CMatrix3 operator - (const CMatrix3& other);
	CMatrix3 operator * (const double k);
	CVictor2D operator * (CVictor2D& p);
	CMatrix3 operator * (const CMatrix3& other);
	CMatrix3& operator += (const CMatrix3& other);
	CMatrix3& operator -= (const CMatrix3& other);
	CMatrix3& operator *= (const double k);
	CMatrix3& operator *= (const CMatrix3& other);

	void ShowData(char* MatrixName);
	//==================================属性=========================
	_CMATRIX3 m_Matrix;

protected:
private:
};
#endif