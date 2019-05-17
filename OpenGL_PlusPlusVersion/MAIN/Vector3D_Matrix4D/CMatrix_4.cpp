#ifndef __CMATRIX4_H__
#define __CMATRIX4_H__
#include "CVector3D.h"
#include "CMatrix_4.h"

void CMatrix_4::Identity()
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			if (i == j)
			{
				m.mf4[i][j] = 1.0f;
			}
			else
			{
				m.mf4[i][j] = 0;
			}
		}
	}
}
void CMatrix_4::Zero()
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			m.mf4[i][j] = 0;
		}
	}
}

CMatrix_4 CMatrix_4::operator*(const CMatrix_4& _m)
{
	CMatrix_4 temp;
	temp.Zero();
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			for (int k = 0; k < 4; k++)
			{
				temp.m.mf4[i][j] += m.mf4[i][k] * _m.m.mf4[k][j];
			}
		}
	}
	return temp;
}

CMatrix_4& CMatrix_4::operator*=(const CMatrix_4& _m)
{
	CMatrix_4 temp;
	temp.Zero();
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			for (int k = 0; k < 4; k++)
			{
				temp.m.mf4[i][j] += m.mf4[i][k] * _m.m.mf4[k][j];
			}
		}
	}
	*this = temp;
	return *this;
}



inline CVector3D operator*(const CVector3D &v,const CMatrix_4& _m)
{
	float tt[4]={v.x,v.y,v.z,1.0f};
	float tf[4]={0,0,0,0};
	for (int i=0;i<4;i++)
	{
		for (int j=0;j<4;j++)
		{
			tf[i] += tt[i] *_m.m.mf4[j][i];
		}
	}
	CVector3D temp(tf[0],tf[1],tf[2]);
	temp /= tf[3];
	return temp;
}
#endif