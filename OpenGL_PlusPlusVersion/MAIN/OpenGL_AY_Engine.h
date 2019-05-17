#pragma once
#include <iostream>
#include <glew.h>//OpenGL头文件
#include <glut.h>//创建管理OpenGL窗口相关函数
#include "OpenGLDefine/OpenGL_Define.h"
#include <Windows.h>
#pragma comment(lib, "glew32.lib")

#include "HeaderFile/HeaderFile.h"

#define ATENGINE           ATEngine::Interface()

#define AT ATENGINE

#define ATVARIABLE       ATEngine_Variable::Interface()

#define ATENGINE_MAINDRAW(MAINDRAW) \
               ATENGINE->ATENGINE_OnRuning(MAINDRAW);

#define ATENGINE_ONWINDOWSCHANGE(ONWINDOWSCHANGE) \
               ATENGINE->ATENGINE_OnWindowsChange(ONWINDOWSCHANGE);

#define ATENGINE_ONIDLE(ONIDLE) \
               ATENGINE->ATENGINE_OnIdle(ONIDLE);

#define ATENGINE_ONORDINARYKEYBOARDDOWN(ONORDINARYKEYBOARDDOWN) \
               ATENGINE->ATENGINE_OnOrdinaryKeyboardDownEvent(ONORDINARYKEYBOARDDOWN);

#define ATENGINE_ONSPECIAKEYBOARDDOWN(ONSPECIAKEYBOARDDOWN) \
               ATENGINE->ATENGINE_OnSpecialKeyboardDownEvent(ONSPECIAKEYBOARDDOWN);

#define ATENGINE_ONORDINARYKEYBOARDUP(ONORDINARYKEYBOARDUP) \
               ATENGINE->ATENGINE_OnOrdinaryKeyboardUpEvent(ONORDINARYKEYBOARDUP);

#define ATENGINE_ONSPECIAKEYBOARDUP(ONSPECIAKEYBOARDUP) \
               ATENGINE->ATENGINE_OnSpecialKeyboardUpEvent(ONSPECIAKEYBOARDUP);

#define ATENGINE_ONMOUSECILCKEVENT(ONMOUSECILCKEVENT) \
               ATENGINE->ATENGINE_OnMouseClickEvent(ONMOUSECILCKEVENT);

#define ATENGINE_ONMOUSEMOVEEVENT(ONMOUSEMOVEEVENT) \
               ATENGINE->ATENGINE_OnMouseMoveEvent(ONMOUSEMOVEEVENT);

#define ATENGINE_ONMOUSEPASSIVEEVENT(ONMOUSEPASSIVEEVENT) \
               ATENGINE->ATENGINE_OnMousePassiveEvent(ONMOUSEPASSIVEEVENT);

//不建议用
#define ATENGINE_ONTIMEREND(MILLISECOND,ONTIMEREND,TIMERID) \
               ATENGINE->ATENGINE_OnSetTimerEnd((MILLISECOND), (ONTIMEREND), (TIMERID));


class ATROOT
{
public:
	BITMAPFILEHEADER m_bf;
	BITMAPINFOHEADER m_bi;
	LPPIXCOLOR *m_BitMapRGBData = NULL;

	ATROOT();
	~ATROOT();
	/*
	LPPIXCOLOR *RGBData = NULL;
		ATENGINE->LoadBitMap("1.bmp", &RGBData);
		glBegin(GL_POINTS);
				for (int i = 0; i < ATENGINE->GetBitMapHeight(); i++)
					{
						for (int j = 0; j < ATENGINE->GetBitMapWidth(); j++)
							{
								glColor3f(RGBData[i][j].R / 255.0f, RGBData[i][j].G / 255.0f, RGBData[i][j].B / 255.0f);
								glVertex2f(j,i);
							}
					}
	glEnd();
	*/
	//::::::::::::::::::::::::不建议用::::::::::::::::::::::::::::::::需要手动释放
	int LoadBitMap(const char *FileName, LPPIXCOLOR **BitMapData);
	/*
	LPPIXCOLOR *RGBData = NULL;
	ATENGINE->LoadBitMapRGBData("1.bmp", &RGBData);
	glRasterPos2f(0, 0);
	glPixelZoom(1, 1);
	glDrawPixels(
		ATENGINE->GetBitMapWidth(), ATENGINE->GetBitMapHeight(),
		GL_BGR_EXT, GL_UNSIGNED_BYTE,
		RGBData);
	*/
	//:::::::::::::::::::::::::不建议用:::::::::::::::::::::::::::::::需要手动释放
	int LoadBitMapRGBData(const char *FileName, LPPIXCOLOR **BitMapRGBData);
	//::::::::::::::::::::::::::::::::::::::::::::::::::::::::::不需要手动释放
	LPPIXCOLOR **LoadBitMapRGBData(const char *FileName);
	//释放的是外部的加载的位图数据
	void DeleteBitMap(LPPIXCOLOR **BitMapData);

	//直接绘制颜色数据
	//:::::::::::::::::::::::::::::::::::::GL_RGB:::::::::::::::: GL_UNSIGNED_BYTE
	void DrawRGB_DATA(float Begin_X, float Begin_Y, float Scale_X, float Scale_Y, float Width, float Height, unsigned int Format = GL_RGB, unsigned int DataType = GL_UNSIGNED_BYTE, void *RGB = NULL);
	void DrawRGB_DATA(ATATPOS2D Begin, ATATSCALE2D Scale, ATATCONTENTSIZE Size, unsigned int Format = GL_RGB, unsigned int DataType = GL_UNSIGNED_BYTE, void *RGB = NULL);


	LONG GetBitMapWidth();
	LONG GetBitMapHeight();
	LPPIXCOLOR **GetBitMapRGBData();
};


class ATEngine_Variable
{
	AT_RGBA m_ClearColor;

	unsigned int m_glClear;

	BOOL m_EnablePoint;

	double m_Fovy;
	double m_Aspect;
	double m_ZNear;
	double m_ZFar;

public:
	//ATEngine_Variable 单列
	static ATEngine_Variable *Interface();

	void SetClearColor(float R = 0.0f, float G = 0.0f, float B = 0.0f, float Alpha = 1.0f);
	ATRGBA *GetClearColor();


	//GL_COLOR_BUFFER_BIT 表示要清空像素信息
	//GL_DEPTH_BUFFER_BIT 表示要清空深度缓冲信息（每一次都使用远截面的z值为清除数值）
	void SetglClear(unsigned int glClear = GL_COLOR_BUFFER_BIT);
	unsigned int *GetglClear();


	/*
		参考
		90.0,//上下界面夹角
		1.0,//宽高比例
		0.3,//近截面距离
		1000.0);//远截面距离
	*/
	//设置摄像机参数
	void SetFAZZ(double Fovy = 90.0, double Aspect = 1.0, double ZNear = 0.3, double ZFar = 1000.0);
	double GetF();
	double GetA();
	double GetZ();
	double Get_Z();
private:
	ATEngine_Variable();
	~ATEngine_Variable();
};


//ATEngine_Variable 的初始化窗口时的变量要改变一定要在初始化前设置

class ATEngine :public ATROOT
{

public:
	//ATEngine 单列
	static ATEngine *Interface();

	//初始化窗口
	void Init(DWORD Init, int *Argc, char **Argv);

	//初始化_OpenGL的显示模式
	/*
		GLUT_SINGLE 单缓冲
		GLUT_RGBA 颜色缓冲区

		CALL:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
		GLUT_SINGLE | GLUT_RGBA 单缓冲 + 颜色缓冲区
	*/
	void InitMode(unsigned int Define);
	//初始化_OpenGL的显示模式
	/*
		GLUT_SINGLE 单缓冲
		GLUT_RGBA 颜色缓冲区

		CALL:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
		GLUT_SINGLE | GLUT_RGBA 单缓冲 + 颜色缓冲区
		GLUT_DOUBLE | GLUT_RGBA 双缓冲 + 颜色缓冲区
	*/
	void InitMode(unsigned int Define, int window_X = 100, int window_Y = 100, int Width = 800, int Height = 600);

	//初始化_设置窗口客户区相对于桌面左上角的位置
	void InitWindowPos(int window_X = 0, int window_Y = 0);

	//初始化_设置窗口的像素宽高(也就是客户区的宽高)
	void InitWindowSize(int Width = 800, int Height = 600);

	//初始化_创建窗口，填写窗口标题栏的文字
	void InitCreateWindows(const char *WindowName = "ATENGINE");


	//引擎主循环
	void ATENGINEMAIN_Loop();

private:

	ATEngine();

	~ATEngine();

	//初始化_设置的用于清除上一次绘制的颜色数据的颜色（相当于背景颜色）
	void InitClearColor();

public:
	//主绘制函数
	void ATENGINE_OnRuning(void(*MainDisplay)());
	//绘制
	static void ATENGINE_Runing_Draw_Begin();

	//把缓冲中的数据写出
	static void ATENGINE_Runing_Draw_End();

	//FPS刷新
	//不要在函数中塞打印函数之类的,会影响FPS,只用于展示刷新的速度
	//建议用//ATENGINE->ATENGINE_RefreshDraw();函数
	static void ATENGINE_FPSDRAW(DWORD FPS);

	//交换缓冲区
	static void ATENGINE_SWAPBUFFERS();

	//与glBegin();成对
	static void DrawEnd();

	//控制台
	static void Console();

	//开启功能
	/*
	GL_CULL_FACE //允许面裁剪
	GL_DEPTH_TEST //开启深度测试

	*/
	static void ATENGINE_Enable(unsigned int FUNCTION = GL_CULL_FACE);

	//关闭功能
	/*
	GL_DEPTH_TEST //关闭深度测试
	*/
	static void ATENGINE_Disable(unsigned int FUNCTION = GL_DEPTH_TEST);

	//开启客户状态的支持
	/*
	GL_VERTEX_ARRAY //顶点数组支持
	GL_COLOR_ARRAY //颜色数组支持
	*/
	static void ATENGINE_EnableCilentState(unsigned int FUNCTION = GL_VERTEX_ARRAY);


	//裁那一面
	/*
	GL_BACK 裁剪掉背面
	*/
	static void ATENGINE_CULLFACE(unsigned int CULLFACE = GL_BACK);


	//回调函数
	//窗口大小和激活状态改变是会调用
	void ATENGINE_OnWindowsChange(void(*OnWindowsChange)(int Width, int Height));

	//普通键盘按键回调
	void ATENGINE_OnOrdinaryKeyboardDownEvent(void(*OnOrdinaryKeyboardDownEvent)(unsigned char Key, int X, int Y));
	void ATENGINE_OnOrdinaryKeyboardUpEvent(void(*OnOrdinaryKeyboardUpEvent)(unsigned char Key, int X, int Y));
	//功能键盘按键回调
	void ATENGINE_OnSpecialKeyboardDownEvent(void(*OnSpecialKeyboardDownEvent)(int Key, int X, int Y));
	void ATENGINE_OnSpecialKeyboardUpEvent(void(*OnSpecialKeyboardUpEvent)(int Key, int X, int Y));

	//鼠标回调
	//鼠标完整的点击事件
	//:::::::::::::::::::::::::::::::::::::::::::::::::::左中右前滚轮后滚轮 0,1,2,3,4   :::::::::::::::::::::按下抬起 0,1
	void ATENGINE_OnMouseClickEvent(void(*OnMouseClickEvent)(int Button, int State, int Mouse_X, int Mouse_Y));
	//鼠标滑动
	void ATENGINE_OnMouseMoveEvent(void(*OnMouseMoveEvent)(int Mouse_X, int Mouse_Y));
	//鼠标拖拽
	void ATENGINE_OnMousePassiveEvent(void(*OnMousePassiveEvent)(int Mouse_X, int Mouse_Y));


	//设置定时器
	//每多少毫秒调用哪个时钟
	/*
		void OnTimerEnd(int Timer_ID)
		{
			switch (Timer_ID)
			{
				case 10086:
					{
							ATENGINE->ATENGINE_PostRedisplayOnTimerBegin();
							std::cout << "10086" << std::endl;
							ATENGINE_ONTIMEREND(100, OnTimerEnd, 10086);
							//glutTimerFunc(100, OnTimerEnd, 10086);
					}; break;
				case 1008611:
					{
							ATENGINE->ATENGINE_PostRedisplayOnTimerBegin();
							std::cout << "1008611" << std::endl;
							ATENGINE_ONTIMEREND(200, OnTimerEnd, 1008611);
					}; break;
			}
		}
	*/
	//:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::不建议用
	void ATENGINE_OnSetTimerEnd(unsigned int Millisecond, void(*OnTimerEnd)(int Timer_ID), int TimerID);
	//投递重新绘制消息
	void ATENGINE_PostRedisplayOnTimerBegin();

	//刷新绘制
	void ATENGINE_RefreshDraw();

	//窗口空闲时调用
	void ATENGINE_OnIdle(void(*OnIdle)());
private:
	//默认调用设置的颜色数据来清除上一次的颜色数据
	static void ATENGINE_Runing_Draw_glClear();

public:
	//:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::开启功能


public:
	//矩阵视口相机
	//2D正交投影
	void ATENGINE_WindowsChangeMatrixModeAndOrtho2D(unsigned int MatrixMode = GL_PROJECTION, double Width = 0, double Height = 0, MATRIXMODE SourcePoint = MATRIXMODE::CENTER);

	//3D透视投影 开始的第一波不会架摄像机
	void ATENGINE_WindowsChangeMatrixModeAndOrtho3D(unsigned int MatrixMode = GL_PROJECTION, double Width = 0, double Height = 0, MATRIXMODE SourcePoint = MATRIXMODE::CENTER);

	/*
		参考
		90.0,//上下界面夹角
		1.0,//宽高比例
		0.3,//近截面距离
		1000.0);//远截面距离
	*/
	//设置摄像机参数
	void SetCamer(double Fovy,double Aspect,double ZNear,double ZFar);

	//::::::::::::::::旋转:平移:::::::::::::::::::::::::::::::::::::::需要手动设置矩阵模式
	void ATENGINE_MatrixMode(unsigned int MatrixMode = GL_MODELVIEW);
public:
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
	//GL_POLYGON			多边形（ >= 3个顶点）
	/*
	void ATENGINE_MatrixMode(unsigned int MatrixMode = GL_MODELVIEW);
	*/
	//::::::::::::::::旋转:平移:::::::::::::::::::::::::::::::::::::::需要手动设置矩阵模式和自己加上:::::::----->ATENGINE->DrawEnd();
	void EnableBase(unsigned int Base);

	void Color3F(float R, float G, float B);
	void Color3F(ATATRGB ATAT_RGB);
	void Color3F(ATATRGBA ATAT_RGBA);
	void Color3UChar(unsigned char R, unsigned char G, unsigned char B);
	void Color3(unsigned char R, unsigned char G, unsigned char B);

	void Color4F(float R, float G, float B, float A);
	void Color4F(ATATRGB ATAT_RGB);
	void Color4F(ATATRGBA ATAT_RGBA);
	void Color4UChar(unsigned char R, unsigned char G, unsigned char B, unsigned char A);
	void Color4(unsigned char R, unsigned char G, unsigned char B, unsigned char A);

	//开启画点
	void Enable_Points();

	//点
	void Draw_Points(float X, float Y);
	void Draw_Points(float R, float G, float B, float X, float Y);
	//填0隔开重载
	void Draw_Points(float R, float G, float B, float A, int *Null, float X, float Y);

	void Draw_Points(float X, float Y, float Z);
	void Draw_Points(float R, float G, float B, float X, float Y, float Z);
	void Draw_Points(float R, float G, float B, float A, float X, float Y, float Z);

	void Draw_Points(ATATPOS2D PointPos);
	void Draw_Points(ATATRGB ATAT_RGB, ATATPOS2D PointPos);
	void Draw_Points(ATATRGBA ATAT_RGBA, ATATPOS2D PointPos);

	void Draw_Points(ATATPOS3D PointPos);
	void Draw_Points(ATATRGB ATAT_RGB, ATATPOS3D PointPos);
	void Draw_Points(ATATRGBA ATAT_RGBA, ATATPOS3D PointPos);
public:
	//创建三角形
	void CreateTriangle(float BeginPoint_X, float BeginPoint_Y, float CenterPoint_X, float CenterPoint_Y, float EndPoint_X, float EndPoint_Y);
	void CreateTriangle(
		float R_B, float G_B, float B_B, float BeginPoint_X, float BeginPoint_Y,
		float R_C, float G_C, float B_C, float CenterPoint_X, float CenterPoint_Y,
		float R_E, float G_E, float B_E, float EndPoint_X, float EndPoint_Y);
	//填0隔开重载
	void CreateTriangle(
		float R_B, float G_B, float B_B, float A_B, int *Null_B, float BeginPoint_X, float BeginPoint_Y,
		float R_C, float G_C, float B_C, float A_C, int *Null_C, float CenterPoint_X, float CenterPoint_Y,
		float R_E, float G_E, float B_E, float A_E, int *Null_E, float EndPoint_X, float EndPoint_Y);

	void CreateTriangle(
		float BeginPoint_X, float BeginPoint_Y, float BeginPoint_Z,
		float CenterPoint_X, float CenterPoint_Y, float CenterPoint_Z,
		float EndPoint_X, float EndPoint_Y, float EndPoint_Z);
	void CreateTriangle(
		float R_B, float G_B, float B_B, float BeginPoint_X, float BeginPoint_Y, float BeginPoint_Z,
		float R_C, float G_C, float B_C, float CenterPoint_X, float CenterPoint_Y, float CenterPoint_Z,
		float R_E, float G_E, float B_E, float EndPoint_X, float EndPoint_Y, float EndPoint_Z);
	void CreateTriangle(
		float R_B, float G_B, float B_B, float A_B, float BeginPoint_X, float BeginPoint_Y, float BeginPoint_Z,
		float R_C, float G_C, float B_C, float A_C, float CenterPoint_X, float CenterPoint_Y, float CenterPoint_Z,
		float R_E, float G_E, float B_E, float A_E, float EndPoint_X, float EndPoint_Y, float EndPoint_Z);



	void CreateTriangle(ATATPOS2D BeginPoint, ATATPOS2D CenterPoint, ATATPOS2D EndPoint);
	void CreateTriangle(
		ATATRGB ATAT_RGB_B, ATATPOS2D BeginPoint,
		ATATRGB ATAT_RGB_C, ATATPOS2D CenterPoint,
		ATATRGB ATAT_RGB_E, ATATPOS2D EndPoint);
	void CreateTriangle(
		ATATRGBA ATAT_RGBA_B, ATATPOS2D BeginPoint,
		ATATRGBA ATAT_RGBA_C, ATATPOS2D CenterPoint,
		ATATRGBA ATAT_RGBA_E, ATATPOS2D EndPoint);

	void CreateTriangle(ATATPOS3D BeginPoint, ATATPOS3D CenterPoint, ATATPOS3D EndPoint);
	void CreateTriangle(
		ATATRGB ATAT_RGB_B, ATATPOS3D BeginPoint,
		ATATRGB ATAT_RGB_C, ATATPOS3D CenterPoint,
		ATATRGB ATAT_RGB_E, ATATPOS3D EndPoint);
	void CreateTriangle(
		ATATRGBA ATAT_RGBA_B, ATATPOS3D BeginPoint,
		ATATRGBA ATAT_RGBA_C, ATATPOS3D CenterPoint,
		ATATRGBA ATAT_RGBA_E, ATATPOS3D EndPoint);

	//创建凸四边形
	void CreateQuadrangle(
		float BeginPoint_X, float BeginPoint_Y,
		float CenterPoint_X_0, float CenterPoint_Y_0,
		float CenterPoint_X_1, float CenterPoint_Y_1,
		float EndPoint_X, float EndPoint_Y);
	void CreateQuadrangle(
		float R_B, float G_B, float B_B, float BeginPoint_X, float BeginPoint_Y,
		float R_C_0, float G_C_0, float B_C_0, float CenterPoint_X_0, float CenterPoint_Y_0,
		float R_C_1, float G_C_1, float B_C_1, float CenterPoint_X_1, float CenterPoint_Y_1,
		float R_E, float G_E, float B_E, float EndPoint_X, float EndPoint_Y);
	//填0隔开重载
	void CreateQuadrangle(
		float R_B, float G_B, float B_B, float A_B, int *Null_B, float BeginPoint_X, float BeginPoint_Y,
		float R_C_0, float G_C_0, float B_C_0, float A_C_0, int *Null_C_0, float CenterPoint_X_0, float CenterPoint_Y_0,
		float R_C_1, float G_C_1, float B_C_1, float A_C_1, int *Null_C_1, float CenterPoint_X_1, float CenterPoint_Y_1,
		float R_E, float G_E, float B_E, float A_E, int *Null_E, float EndPoint_X, float EndPoint_Y);

	void CreateQuadrangle(
		float BeginPoint_X, float BeginPoint_Y, float BeginPoint_Z,
		float CenterPoint_X_0, float CenterPoint_Y_0, float CenterPoint_Z_0,
		float CenterPoint_X_1, float CenterPoint_Y_1, float CenterPoint_Z_1,
		float EndPoint_X, float EndPoint_Y, float EndPoint_Z);
	void CreateQuadrangle(
		float R_B, float G_B, float B_B, float BeginPoint_X, float BeginPoint_Y, float BeginPoint_Z,
		float R_C_0, float G_C_0, float B_C_0, float CenterPoint_X_0, float CenterPoint_Y_0, float CenterPoint_Z_0,
		float R_C_1, float G_C_1, float B_C_1, float CenterPoint_X_1, float CenterPoint_Y_1, float CenterPoint_Z_1,
		float R_E, float G_E, float B_E, float EndPoint_X, float EndPoint_Y, float EndPoint_Z);
	void CreateQuadrangle(
		float R_B, float G_B, float B_B, float A_B, float BeginPoint_X, float BeginPoint_Y, float BeginPoint_Z,
		float R_C_0, float G_C_0, float B_C_0, float A_C_0, float CenterPoint_X_0, float CenterPoint_Y_0, float CenterPoint_Z_0,
		float R_C_1, float G_C_1, float B_C_1, float A_C_1, float CenterPoint_X_1, float CenterPoint_Y_1, float CenterPoint_Z_1,
		float R_E, float G_E, float B_E, float A_E, float EndPoint_X, float EndPoint_Y, float EndPoint_Z);


	void CreateQuadrangle(ATATPOS2D BeginPoint, ATATPOS2D CenterPoint_0, ATATPOS2D CenterPoint_1, ATATPOS2D EndPoint);
	void CreateQuadrangle(
		ATATRGB ATAT_RGB_B, ATATPOS2D BeginPoint,
		ATATRGB ATAT_RGB_C_0, ATATPOS2D CenterPoint_0,
		ATATRGB ATAT_RGB_C_1, ATATPOS2D CenterPoint_1,
		ATATRGB ATAT_RGB_E, ATATPOS2D EndPoint);
	void CreateQuadrangle(
		ATATRGBA ATAT_RGB_B, ATATPOS2D BeginPoint,
		ATATRGBA ATAT_RGB_C_0, ATATPOS2D CenterPoint_0,
		ATATRGBA ATAT_RGB_C_1, ATATPOS2D CenterPoint_1,
		ATATRGBA ATAT_RGB_E, ATATPOS2D EndPoint);
	void CreateQuadrangle(ATATPOS3D BeginPoint, ATATPOS3D CenterPoint_0, ATATPOS3D CenterPoint_1, ATATPOS3D EndPoint);
	void CreateQuadrangle(
		ATATRGB ATAT_RGB_B, ATATPOS3D BeginPoint,
		ATATRGB ATAT_RGB_C_0, ATATPOS3D CenterPoint_0,
		ATATRGB ATAT_RGB_C_1, ATATPOS3D CenterPoint_1,
		ATATRGB ATAT_RGB_E, ATATPOS3D EndPoint);
	void CreateQuadrangle(
		ATATRGBA ATAT_RGB_B, ATATPOS3D BeginPoint,
		ATATRGBA ATAT_RGB_C_0, ATATPOS3D CenterPoint_0,
		ATATRGBA ATAT_RGB_C_1, ATATPOS3D CenterPoint_1,
		ATATRGBA ATAT_RGB_E, ATATPOS3D EndPoint);
public:
	/*
		int ID = ATENGINE->CreateDrawList(2);
		ATENGINE->EnableBase(GL_QUADS);
		ATENGINE->Color3F(ATATRGB(0.0f, 1.0f, 0.0f));
		ATENGINE->Draw_Points(ATATPOS2D(-50, +50));
		ATENGINE->Draw_Points(ATATPOS2D(-50, -50));
		ATENGINE->Draw_Points(ATATPOS2D(+50, -50));
		ATENGINE->Draw_Points(ATATPOS2D(+50, +50));
		ATENGINE->DrawEnd();
		ATENGINE->EnableBase(GL_QUADS);
		ATENGINE->Color3F(ATATRGB(1.0f, 1.0f, 0.0f));
		ATENGINE->Draw_Points(ATATPOS2D(-25, +25));
		ATENGINE->Draw_Points(ATATPOS2D(-25, -25));
		ATENGINE->Draw_Points(ATATPOS2D(+25, -25));
		ATENGINE->Draw_Points(ATATPOS2D(+25, +25));
		ATENGINE->DrawEnd();
		ATENGINE->EndDrawList();

		int ID2 = ATENGINE->CreateDrawList(1);
		glNewList(ID2, GL_COMPILE);
		ATENGINE->CreateTriangle(
		ATATRGB::RED, ATATPOS2D::ZERO,
		ATATRGB::GREEN, ATATPOS2D(0, 200),
		ATATRGB::BLUE, ATATPOS2D(200, 200));
		ATENGINE->DrawEnd();
		ATENGINE->EndDrawList();
	*/
	/*
		必须是	glBegin() 的绘制
	*/
	//创建绘图列表不绘制
	unsigned int CreateDrawList(unsigned int Number);
	//创建绘图列表并绘制一次
	unsigned int CreateDrawListAndDraw(unsigned int Number);
	//单个绘图列表绘制
	void DrawDrawList(unsigned int DrawListID);
	//多个绘图列表绘制
	//GL_UNSIGNED_INT
	void DrawDrawList_s(unsigned int DrawListIDNum, unsigned int ArrType = GL_UNSIGNED_INT, unsigned int *Arr = NULL);
	//结束绘图列表
	void EndDrawList();
	//删除绘图列表
	void DeleteDrawList(unsigned int DrawListID, unsigned int Number);
public:
	void Translate(float X, float Y, float Z);
	void Translate(ATATPOS3D ATATPos3D);
	void Rotate(float Angle, float X, float Y, float Z);
	void Rotate(float Angle, ATATPOS3D ATATPos3D);
};



/*

///	glScalef(0.5,0.5,0.0f);
///	glCallList(1);//绘制单个绘图列表




*/