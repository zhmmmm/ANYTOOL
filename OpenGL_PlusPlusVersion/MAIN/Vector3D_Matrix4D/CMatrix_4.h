#pragma once

class CMatrix_4
{
public:
	union {
		struct {
			float _11, _12, _13, _14;
			float _21, _22, _23, _24;
			float _31, _32, _33, _34;
			float _41, _42, _43, _44;
		};
		float mf4[4][4];
	}m;
public:
	CMatrix_4() { Identity(); }
	void Identity();
	void Zero();

	CMatrix_4 operator*(const CMatrix_4& _m);

	CMatrix_4& operator*=(const CMatrix_4& _m);

	/*
	三阶的变换矩阵
	缩放：			旋转：			平移：
	┏	   ┓		┏      ┓		┏	   ┓
	┃x	0 0┃		┃ c s 0┃		┃1	0 0┃
	┃0	y 0┃		┃-s c 0┃		┃0	1 0┃
	┃0 0 1┃		┃ 0 0 1┃		┃x y 1┃
	┗	   ┛		┗	    ┛		┗	   ┛
	四阶变换矩阵
	缩放：			平移：
	┏	     ┓		┏	     ┓
	┃x	0 0 0┃		┃1	0 0 0┃
	┃0	y 0 0┃		┃0	1 0 0┃
	┃0 0 z 0┃		┃0 0 1 0┃
	┃0 0 0 1┃		┃x y z 1┃
	┗	     ┛		┗	     ┛
	围绕Z轴进行旋转		围绕X轴进行旋转		围绕Y轴进行旋转
	┏	           ┓		┏	          ┓		┏	       ┓
	┃c  s 0 0┃		┃1 0 0 0┃		┃c	 0 -s 0┃
	┃-s c 0 0┃		┃0  c s 0┃		┃0  1  0 0┃
	┃0  0 1 0┃		┃0 -s c 0┃		┃s  0  c 0┃
	┃0  0 0 1┃		┃0  0 0 1┃		┃0  0  0 1┃
	┗	           ┛		┗	          ┛		┗	       ┛
	*/
protected:
private:
};

