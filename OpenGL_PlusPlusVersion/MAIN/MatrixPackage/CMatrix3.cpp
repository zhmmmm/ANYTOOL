#include "CMatrix3.h"
CMatrix3::CMatrix3()
{
	memset(m_Matrix.m,0,sizeof(double)*9);
}
CMatrix3::CMatrix3(const CMatrix3& old)
{
	memcpy(m_Matrix.m,old.m_Matrix.m,sizeof(double)*9);
}
CMatrix3::CMatrix3(double _11,double _12,double _13,double _21,double _22,double _23,double _31,double _32,double _33)
{
	m_Matrix._11=_11;m_Matrix._12=_12;m_Matrix._13=_13;
	m_Matrix._21=_21;m_Matrix._22=_22;m_Matrix._23=_23;
	m_Matrix._31=_31;m_Matrix._32=_32;m_Matrix._33=_33;
}
CMatrix3::CMatrix3(double m[3][3])
{
	memcpy(m_Matrix.m,m,sizeof(double)*9);
}
CMatrix3::CMatrix3(double** m)
{
	memcpy(m_Matrix.m[0],m[0],sizeof(double)*3);
	memcpy(m_Matrix.m[1],m[1],sizeof(double)*3);
	memcpy(m_Matrix.m[2],m[2],sizeof(double)*3);
}
double CMatrix3::GetDet()
{
	double det=m_Matrix._11*m_Matrix._22*m_Matrix._33 
		+ m_Matrix._12*m_Matrix._23*m_Matrix._31 
		+ m_Matrix._13*m_Matrix._21*m_Matrix._32
		- m_Matrix._13*m_Matrix._22*m_Matrix._31
		- m_Matrix._12*m_Matrix._21*m_Matrix._33
		- m_Matrix._11*m_Matrix._23*m_Matrix._32;
	return det;
}
double GetDetRank2(double src[2][2])//求2阶行列式值
{
	double det=src[0][0]*src[1][1]- src[0][1]*src[1][0];
	return det;
}
double GetCofactor(int Row,int Col,_CMATRIX3 src)//取任意行列2阶代数余子式
{
	double temp[4]={};
	double det=0;
	int index=0;
	for (int i=0;i<3;i++)
	{
		for (int j=0;j<3;j++)
		{
			if (i!=Row&&j!=Col)
			{
				temp[index++]=src.m[i][j];
			}
		}
	}
	det=temp[0]*temp[3]-temp[1]*temp[2];
	det*=pow(double(-1),Row+Col);
	return det;	
}
CMatrix3 CMatrix3::Transpose()//求转置矩阵
{
	CMatrix3 temp;
	for (int i=0;i<3;i++)
	{
		for (int j=0;j<3;j++)
		{
			temp.m_Matrix.m[i][j]=m_Matrix.m[j][i];
		}
	}
	return temp;
}
CMatrix3 CMatrix3::Adjoint()//求伴随矩阵
{
	CMatrix3 temp;
	for (int i=0;i<3;i++)
	{
		for (int j=0;j<3;j++)
		{
			temp.m_Matrix.m[j][i]=GetCofactor(i,j,m_Matrix);
		}
	}
	return temp;
}
CMatrix3 CMatrix3::Inverse(bool &IsInverse)//求逆矩阵//传入一个逻辑引用参数，来判断是否可逆
{
	CMatrix3 temp;//初始为0矩阵
	double det=GetDet();
	if (det!=0)
	{
		IsInverse=true;
		temp=Adjoint();
		temp*=(1/det);
		return temp;
	}
	IsInverse=false;
	return temp;
}
CMatrix3 CMatrix3::GetScaleMtr(double x_ratio,double y_ratio)//比例变换矩阵
{
CMatrix3 T(x_ratio,0,0,
		   0,y_ratio,0,
		   0,0,1);
return T;
}
CMatrix3 CMatrix3::GetEqlScaleMtr(double s_ratio)//等比例变换矩阵
{
CMatrix3 T(1/s_ratio,0,0,
		   0,1/s_ratio,0,
		   0,0,1);//这样处理是不希望要在最后判断H是否为1
return T;
}
CMatrix3 CMatrix3::GetRotateMtr(double angle)//旋转矩阵
{
CMatrix3 T(cos(angle),sin(angle),0,
		   -sin(angle),cos(angle),0,
		   0,0,1
		   );
return T;
}
CMatrix3 CMatrix3::GetTranslationMtr(double x_m,double y_n)//平移
{
CMatrix3 T(1,0,0,
		   0,1,0,
		   x_m,y_n,1
		   );
return T;
}
CMatrix3 CMatrix3::GetX_Symmetry()//X对称变换
{
CMatrix3 T(1,0,0,
		   0,-1,0,
		   0,0,1
		   );
return T;
}
CMatrix3 CMatrix3::GetY_Symmetry()//Y对称变换
{
	CMatrix3 T(-1,0,0,
		0,1,0,
		0,0,1
		);
	return T;
}
CMatrix3 CMatrix3::GetO_Symmetry()//原点对称变换
{
	CMatrix3 T(-1,0,0,
		0,-1,0,
		0,0,1
		);
	return T;
}
CMatrix3 CMatrix3::Get45_Symmetry()//+45°对称变换
{
	CMatrix3 T( 0,1,0,
				1,0,0,
				0,0,1
		);
	return T;
}
CMatrix3 CMatrix3::Get_45_Symmetry()//-45°对称变换
{
	CMatrix3 T(0,-1,0,
		-1,0,0,
		0,0,1
		);
	return T;
}
CMatrix3 CMatrix3::Get_Angle_Symmetry(double angle)//关于过原点任意角度直线的对称变换
{
CMatrix3 T(cos(2*angle),sin(2*angle),0,
		   sin(2*angle),-cos(2*angle),0,
		   0,0,1);
return T;
}
CMatrix3 CMatrix3::GetX_TiltMtr(double angle)//X错切变换
{
	CMatrix3 T(1,tan(angle),0,
		0,1,0,
		0,0,1
		);
	return T;
}
CMatrix3 CMatrix3::GetY_TiltMtr(double angle)//Y错切变换
{
	CMatrix3 T(1,0,0,
		tan(angle),1,0,
		0,0,1
		);
	return T;
}
CMatrix3 CMatrix3::operator + (const CMatrix3& other)
{
	CMatrix3 temp;
	for (int i=0;i<3;i++)
	{
		for (int j=0;j<3;j++)
		{
			temp.m_Matrix.m[i][j]=m_Matrix.m[i][j]+other.m_Matrix.m[i][j];
		}
	}
	return temp;
}
CMatrix3 CMatrix3::operator - (const CMatrix3& other)
{
	CMatrix3 temp;
	for (int i=0;i<3;i++)
	{
		for (int j=0;j<3;j++)
		{
			temp.m_Matrix.m[i][j]=m_Matrix.m[i][j]-other.m_Matrix.m[i][j];
		}
	}
	return temp;
}
CMatrix3 CMatrix3::operator * (const double k)
{
	CMatrix3 temp;
	for (int i=0;i<3;i++)
	{
		for (int j=0;j<3;j++)
		{
			temp.m_Matrix.m[i][j] = m_Matrix.m[i][j]*k;
		}
	}
	return temp;
}
CVictor2D CMatrix3::operator * (CVictor2D& p)
{
	CMatrix3 O(p.GetX(),p.GetY(),1,0,0,0,0,0,0);
	O*=(*this);
	CVictor2D ret(O.m_Matrix._11,O.m_Matrix._12);
	return ret;
}
CMatrix3 CMatrix3::operator * (const CMatrix3& other)
{
	CMatrix3 temp;
	for (int i=0;i<3;i++)
	{
		for (int j=0;j<3;j++)
		{
			for (int k=0;k<3;k++)
			{
				temp.m_Matrix.m[i][j]+=m_Matrix.m[i][k]*other.m_Matrix.m[k][j];
			}
		}
	}
	return temp;
}
CMatrix3& CMatrix3::operator += (const CMatrix3& other)
{
	for (int i=0;i<3;i++)
	{
		for (int j=0;j<3;j++)
		{
			m_Matrix.m[i][j]+=other.m_Matrix.m[i][j];
		}
	}
	return *this;
}
CMatrix3& CMatrix3::operator -= (const CMatrix3& other)
{
	for (int i=0;i<3;i++)
	{
		for (int j=0;j<3;j++)
		{
			m_Matrix.m[i][j]-=other.m_Matrix.m[i][j];
		}
	}
	return *this;
}
CMatrix3& CMatrix3::operator *= (const double k)
{
	for (int i=0;i<3;i++)
	{
		for (int j=0;j<3;j++)
		{
			m_Matrix.m[i][j]*=k;
		}
	}
	return *this;
}
CMatrix3& CMatrix3::operator *= (const CMatrix3& other)
{
	CMatrix3 temp;
	for (int i=0;i<3;i++)
	{
		for (int j=0;j<3;j++)
		{
			for (int k=0;k<3;k++)
			{
				temp.m_Matrix.m[i][j]+=m_Matrix.m[i][k]*other.m_Matrix.m[k][j];
			}
		}
	}
	memcpy(m_Matrix.m,temp.m_Matrix.m,sizeof(double)*9);
	return *this;
}
void CMatrix3::ShowData(char* MatrixName)
{
	if (MatrixName!=NULL)
	{
		cout<<MatrixName<<"[3×3] = \n";
	}else
	{
		cout<<"A[3×3] = \n";
	}
	cout<<"╭                                      ╮\n";
	for (int i=0;i<3;i++)
	{
		cout<<"│";
		for (int j=0;j<3;j++)
		{
			printf("%12.6lf",m_Matrix.m[i][j]);
			if (j<2)
			{
				cout<<",";
			}
		}
		cout<<"│"<<endl;
	}
	cout<<"╰                                      ╯\n";
}