#include "OpenGL_Class.h"
#include "CMyBass.h"
#include "TextureManager.h"


#ifndef _DEBUG
#pragma comment(linker,"/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")
#endif

float g_Angle = 0.0f;
float g_Camer_Y = 10;
int g_Width = 800;
int g_Height = 600;
unsigned char* pBmp = NULL;
unsigned char* pBmp2 = NULL;

GLuint tid[2];//用于存储创建的纹理的ID的数组


//顶点数组
float rc[] = {
	-20,+20,0,
	-20,-20,0,
	+20,-20,0,
	+20,+20,0
};
float cl[] = {
	255,0,0,
	255,255,255,
	0,0,255,
	0,255,0
};
//纹理坐标（uv）数组
float uv[] = {
	0,1,
	0,0,
	1,0,
	1,1
};

//将顶点颜色纹理UV信息合在一起写法
float tg[] = {
	-20,+20,0,255,0,0,0,1,
	-20,-20,0,255,255,255,0,0,
	+20,-20,0,0,0,255,1,0,
	+20,+20,0,0,255,0,1,1
};
unsigned int index[] = {
	0,1,2,
	0,2,3
};

void Display()
{
	//调用设置的颜色来清除上一次的颜色数据
	glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT | GL_STENCIL_BUFFER_BIT);
	//中间的就是用于绘制的部分在此书写代码
	//OpenGL的一些基本图元类型
	//GL_POINTS				点(一个顶点)
	//GL_LINES				线段(2个顶点)
	//GL_LINE_LOOP			封闭线段//会首尾相连
	//GL_LINE_STRIP			连接线段
	//GL_TRIANGLES			三角形（3个顶点）
	//GL_TRIANGLE_STRIP		连接三角形
	//GL_TRIANGLE_FAN		三角形扇？
	//GL_QUADS				凸四边形
	//GL_QUAD_STRIP			连接凸四边形
	//GL_POLYGON			多边形（>=3个顶点）

	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();
	gluLookAt(0, g_Camer_Y, 50, 0, 0, 0, 0, 1, 0);
	glRotated(g_Angle, 0, 1, 0);



	glTranslatef(-30, 0, 0);
	glVertexPointer(3, GL_FLOAT, 32, tg);
	glTexCoordPointer(2,GL_FLOAT,32,tg + 6);
	glBindTexture(GL_TEXTURE_2D, tid[0]);//设置当前使用的纹理为第一张纹理
	glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_INT, index);


	glLoadIdentity();
	gluLookAt(0, g_Camer_Y, 50, 0, 0, 0, 0, 1, 0);
	glTranslatef(+30, 0, 0);
	glVertexPointer(3, GL_FLOAT, 0, rc);
	glTexCoordPointer(2,GL_FLOAT,0,uv);
	glBindTexture(GL_TEXTURE_2D, tid[1]);//设置当前使用的纹理为第二张纹理
	glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_INT, index);

	glutSwapBuffers();
}
//传入的是改变后的窗口大小的宽高
void ReShape(int width, int height)
{
	//设置当前操作的矩阵
	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();//将投影矩阵单位化
	glViewport(0, 0, width, height);//要画到窗口的宽高
	gluPerspective(90.0,1,0.3,1000);//设置透视投影
	//gluOrtho2D(-width / 2, width / 2, -height / 2, height / 2);//设置正交投影
	//gluOrtho2D(0, width, 0, height); //设置正交投影
}
void Indle()
{
	float StartTime = GetTickCount();
	//system("cls");
	static float LastTime = 0;
	if (StartTime - LastTime >= 60.0f)
	{
		glutPostRedisplay();//投递重新绘制的消息
		LastTime = StartTime;
	}
}
void OrdinaryKeyDown(unsigned char Key, int Mouse_X, int Mouse_Y)
{
	if (Key == 13) { exit(0); }
	if (Key == 'W' || Key == 'w')
	{
		g_Camer_Y += 5.0f;
	}
	if (Key == 'S' || Key == 's')
	{
		g_Camer_Y -= 5.0f;
	}
	if (Key == 'A' || Key == 'a')
	{
		g_Angle += 2.0f;
	}
	if (Key == 'D' || Key == 'd')
	{
		g_Angle -= 2.0f;
	}
}
int main(int argc, char **argv)
{
	OPENGL->Init(&argc, argv);
	OPENGL->InitMode(GLUT_DOUBLE | GLUT_RGBA|GLUT_DEPTH|GLUT_STENCIL);
	OPENGL->InitWinPos(100, 100);
	OPENGL->InitWindSize(g_Width, g_Height);
	OPENGL->CreateWindows("OpenGL程序");
	OPENGL->ClearColor(0.0f, 0.0f, 0.0f, 1.0f);
	OPENGL->SerDrawCallback(Display);
	OPENGL->WindSizeOractivation_Reshape(ReShape);
	OPENGL->OrdinaryKeyDown(OrdinaryKeyDown);
	OPENGL->WindIdle(Indle);
	OPENGL->EnableCullFace();
	//开启顶点数组,颜色数组,深度缓冲区,支持纹理2D贴图,UV数组坐标,开启颜色混合,开启模板缓冲区
	OPENGL->Enable_Varied__Buffer__(1, 0, 1, 1, 1,0,0);
	glewInit();
	//============================================================

	glGenTextures(
		//要创建多少个纹理的id
		2,
		//用于接收纹理id的unsigned int数组
		tid);

	//下面的代码设置指定id的纹理为当前纹理
	glBindTexture(GL_TEXTURE_2D, tid[0]);
	//下面所有的操作都是针对当前纹理的

	//设置纹理的采样方式
	//GL_NEAREST：最近点采样，效果差效率高
	//GL_LINEAR：线性插值采样，效果好效率低
	//GL_TEXTURE_MIN_FILTER表示这种采样方式
	//作用在缩小纹理采样上面，所谓缩小就是指
	//的模型三角形的绘制面积小于纹理三角形面
	//积的时候，GL_TEXTURE_MAG_FILTER就表示
	//这种采样作用在放大纹理采样上面，即模型
	//三角形的绘制面积大于纹理三角形面积的时
	//候，一般来说缩小、放大采样都需要设置
	glTexParameterf(
		GL_TEXTURE_2D,
		GL_TEXTURE_MIN_FILTER,
		GL_NEAREST);
	glTexParameterf(
		GL_TEXTURE_2D,
		GL_TEXTURE_MAG_FILTER,
		GL_NEAREST);




	//////////////////////////////////////////////////////////////////////////
	//加载图片数据
	FILE* pf = NULL;
	fopen_s(&pf, "res/2.bmp", "rb");
	BITMAPFILEHEADER bf;
	BITMAPINFOHEADER bi;

	//跳过了文件头
	fread(&bf, 1, sizeof(bf), pf);
	//跳过了信息头
	fread(&bi, 1, sizeof(bi), pf);
	//将剩余的颜色数据一次性读入
	pBmp2 = new unsigned char[bi.biSizeImage];
	fread(pBmp2, 1, bi.biSizeImage, pf);
	fclose(pf);



	//加载纹理
	glTexImage2D(
		//GL_TEXTURE_2D表示加载二维纹理
		GL_TEXTURE_2D,
		//0表示不创建多级渐进纹理
		0,
		//GL_RGB表示纹理是RGB颜色模式
		GL_RGB,
		//纹理像素宽
		bi.biWidth,
		//纹理像素高
		bi.biHeight,
		//0表示不设置纹理边界
		0,
		//GL_BGR_EXT表示纹理像素的格式为B、G、R的排列
		GL_BGR_EXT,
		//GL_UNSIGNED_BYTE表示纹理像素颜色分量的格式为unsigned char
		GL_UNSIGNED_BYTE,
		//纹理像素颜色的起始地址
		pBmp2);


	//加载第二张图
	//下面的代码设置指定id的纹理为当前纹理
	glBindTexture(GL_TEXTURE_2D, tid[1]);
	//下面所有的操作都是针对当前纹理的

	//设置纹理的采样方式
	//GL_NEAREST：最近点采样，效果差效率高
	//GL_LINEAR：线性插值采样，效果好效率低
	//GL_TEXTURE_MIN_FILTER表示这种采样方式
	//作用在缩小纹理采样上面，所谓缩小就是指
	//的模型三角形的绘制面积小于纹理三角形面
	//积的时候，GL_TEXTURE_MAG_FILTER就表示
	//这种采样作用在放大纹理采样上面，即模型
	//三角形的绘制面积大于纹理三角形面积的时
	//候，一般来说缩小、放大采样都需要设置
	glTexParameterf(
		GL_TEXTURE_2D,
		GL_TEXTURE_MIN_FILTER,
		GL_LINEAR);
	glTexParameterf(
		GL_TEXTURE_2D,
		GL_TEXTURE_MAG_FILTER,
		GL_LINEAR);

	pf = NULL;
	fopen_s(&pf, "res/testDetail.bmp", "rb");

	fread(&bf, 1, sizeof(bf), pf);
	fread(&bi, 1, sizeof(bi), pf);
	pBmp = new unsigned char[bi.biSizeImage];
	fread(pBmp, 1, bi.biSizeImage, pf);
	fclose(pf);
	//加载纹理
	glTexImage2D(
		//GL_TEXTURE_2D表示加载二维纹理
		GL_TEXTURE_2D,
		//0表示不创建多级渐进纹理
		0,
		//GL_RGB表示纹理是RGB颜色模式
		GL_RGB,
		//纹理像素宽
		bi.biWidth,
		//纹理像素高
		bi.biHeight,
		//0表示不设置纹理边界
		0,
		//GL_BGR_EXT表示纹理像素的格式为B、G、R的排列
		GL_BGR_EXT,
		//GL_UNSIGNED_BYTE表示纹理像素颜色分量的格式为unsigned char
		GL_UNSIGNED_BYTE,
		//纹理像素颜色的起始地址
		pBmp);


	glBindTexture(GL_TEXTURE_2D, 0);//释放操作的纹理目标

	delete[] pBmp2;
	pBmp2 = NULL;
	delete[] pBmp;
	pBmp = NULL;



	//============================================================

	OPENGL->MainWindLoop();
	glDeleteTextures(2, tid);
	return 0;
}