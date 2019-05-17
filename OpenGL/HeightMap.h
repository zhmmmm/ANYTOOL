#ifndef __HEIGHT_MAP_H__
#define __HEIGHT_MAP_H__
#include <iostream>
#include <gl/glew.h>
#include <gl/glut.h>

class HeightMap
{
public:
	HeightMap();
	~HeightMap();

	bool CreateFromBMP(
		const char* bmpfile,//灰度图路径
		float h,//生成地形的最高Y值
		int xwidth,//x方向格子数量
		int zwidth,//z方向格子数量
		float space//表示单位格子的宽
		);

	void DrawMap();//绘制地形
protected:
private:
	float* mVertext;//顶点数组
	unsigned int* mIndex;//索引数组
	unsigned int mVertextCount;//顶点个数
	unsigned int mIndexCount;//索引数
};
#endif