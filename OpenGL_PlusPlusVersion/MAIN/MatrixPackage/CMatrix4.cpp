#include "CMatrix4.h"
CMatrix4::CMatrix4()
{
	memset(m_Matrix.m,0,sizeof(double)*16);
}
CMatrix4::CMatrix4(const CMatrix4& old)
{
	memcpy(m_Matrix.m,old.m_Matrix.m,sizeof(double)*16);
}
CMatrix4::CMatrix4(double _11,double _12,double _13,double _14,
				   double _21,double _22,double _23,double _24,
				   double _31,double _32,double _33,double _34,
				   double _41,double _42,double _43,double _44
				   )
{
	m_Matrix._11=_11;m_Matrix._12=_12;m_Matrix._13=_13,m_Matrix._14=_14;
	m_Matrix._21=_21;m_Matrix._22=_22;m_Matrix._23=_23,m_Matrix._24=_24;
	m_Matrix._31=_31;m_Matrix._32=_32;m_Matrix._33=_33,m_Matrix._34=_34;
	m_Matrix._41=_41;m_Matrix._42=_42;m_Matrix._43=_43,m_Matrix._44=_44;
}
CMatrix4::CMatrix4(double m[4][4])
{
	memcpy(m_Matrix.m,m,sizeof(double)*16);
}
CMatrix4::CMatrix4(double** m)
{
	memcpy(m_Matrix.m[0],m[0],sizeof(double)*4);
	memcpy(m_Matrix.m[1],m[1],sizeof(double)*4);
	memcpy(m_Matrix.m[2],m[2],sizeof(double)*4);
	memcpy(m_Matrix.m[3],m[3],sizeof(double)*4);
}
double GetDetRank3(double src[3][3])//求3阶行列式值
{
	double det=src[0][0]*src[1][1]*src[2][2] 
	+ src[0][1]*src[1][2]*src[2][0] 
	+ src[0][2]*src[1][0]*src[2][1]
	- src[0][2]*src[1][1]*src[2][0]
	- src[0][1]*src[1][0]*src[2][2]
	- src[0][0]*src[1][2]*src[2][1];
	return det;
}
double GetCofactor(int Row,int Col,_CMATRIX4 src)//取任意行列3阶代数余子式
{
	double temp[9]={};
	double dest[3][3]={};
	double det=0;
	int index=0;
	for (int i=0;i<4;i++)
	{
		for (int j=0;j<4;j++)
		{
			if (i!=Row&&j!=Col)
			{
				temp[index++]=src.m[i][j];
			}
		}
	}
	memcpy(dest,temp,sizeof(double)*9);
	det=pow(double(-1),Row+Col)*GetDetRank3(dest);
	return det;
}
CMatrix4 CMatrix4::Transpose()//求转置矩阵
{
	CMatrix4 temp;
	for (int i=0;i<4;i++)
	{
		for (int j=0;j<4;j++)
		{
			temp.m_Matrix.m[i][j]=m_Matrix.m[j][i];
		}
	}
	return temp;
}
CMatrix4 CMatrix4::Adjoint()//求伴随矩阵
{
	CMatrix4 temp;
	for (int i=0;i<4;i++)
	{
		for (int j=0;j<4;j++)
		{	
			temp.m_Matrix.m[j][i]=GetCofactor(i,j,m_Matrix);
		}
	}
	return temp;
}
CMatrix4 CMatrix4::Inverse(bool &IsInverse)//求逆矩阵//传入一个逻辑引用参数，来判断是否可逆
{
	CMatrix4 temp;//初始为0矩阵
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
double CMatrix4::GetDet()
{
	double det=0;
	for (int i=0;i<4;i++)
	{
		det+=m_Matrix.m[i][0]*GetCofactor(i,0,m_Matrix);
	}
	return det;
}
CMatrix4 CMatrix4::operator + (const CMatrix4& other)
{
	CMatrix4 temp;
	for (int i=0;i<4;i++)
	{
		for (int j=0;j<4;j++)
		{
			temp.m_Matrix.m[i][j]=m_Matrix.m[i][j]+other.m_Matrix.m[i][j];
		}
	}
	return temp;
}
CMatrix4 CMatrix4::operator - (const CMatrix4& other)
{
	CMatrix4 temp;
	for (int i=0;i<4;i++)
	{
		for (int j=0;j<4;j++)
		{
			temp.m_Matrix.m[i][j]=m_Matrix.m[i][j]-other.m_Matrix.m[i][j];
		}
	}
	return temp;
}
CMatrix4 CMatrix4::operator * (const double k)
{
	CMatrix4 temp;
	for (int i=0;i<4;i++)
	{
		for (int j=0;j<4;j++)
		{
			temp.m_Matrix.m[i][j] = m_Matrix.m[i][j]*k;
		}
	}
	return temp;
}
CMatrix4 CMatrix4::operator * (const CMatrix4& other)
{
	CMatrix4 temp;
	for (int i=0;i<4;i++)
	{
		for (int j=0;j<4;j++)
		{
			for (int k=0;k<4;k++)
			{
				temp.m_Matrix.m[i][j]+=m_Matrix.m[i][k]*other.m_Matrix.m[k][j];
			}
		}
	}
	return temp;
}
CMatrix4& CMatrix4::operator += (const CMatrix4& other)
{
	for (int i=0;i<4;i++)
	{
		for (int j=0;j<4;j++)
		{
			m_Matrix.m[i][j]+=other.m_Matrix.m[i][j];
		}
	}
	return *this;
}
CMatrix4& CMatrix4::operator -= (const CMatrix4& other)
{
	for (int i=0;i<4;i++)
	{
		for (int j=0;j<4;j++)
		{
			m_Matrix.m[i][j]-=other.m_Matrix.m[i][j];
		}
	}
	return *this;
}
CMatrix4& CMatrix4::operator *= (const double k)
{
	for (int i=0;i<4;i++)
	{
		for (int j=0;j<4;j++)
		{
			m_Matrix.m[i][j]*=k;
		}
	}
	return *this;
}
CMatrix4& CMatrix4::operator *= (const CMatrix4& other)
{
	CMatrix4 temp;
	for (int i=0;i<4;i++)
	{
		for (int j=0;j<4;j++)
		{
			for (int k=0;k<4;k++)
			{
				temp.m_Matrix.m[i][j]+=m_Matrix.m[i][k]*other.m_Matrix.m[k][j];
			}
		}
	}
	memcpy(m_Matrix.m,temp.m_Matrix.m,sizeof(double)*9);
	return *this;
}
void CMatrix4::ShowData(char* MatrixName)
{
	if (MatrixName!=NULL)
	{
		cout<<MatrixName<<"[4×4] = \n";
	}else
	{
		cout<<"A[4×4] = \n";
	}
	cout<<"╭                                                   ╮\n";
	for (int i=0;i<4;i++)
	{
		cout<<"│";
		for (int j=0;j<4;j++)
		{
			printf("%12.6lf",m_Matrix.m[i][j]);
			if (j<3)
			{
				cout<<",";
			}
		}
		cout<<"│"<<endl;
	}
	cout<<"╰                                                   ╯\n";
}