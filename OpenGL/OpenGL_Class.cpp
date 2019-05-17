#include "OpenGL_Class.h"

#pragma comment(lib, "glew32.lib")

OpenGL::OpenGL() {}
OpenGL *OpenGL::Interface()
{
	static OpenGL opengl;
	return &opengl;
}
//初始化_glut库
void OpenGL::Init(int *argc, char **argv)
{
	glutInit(argc, argv);

}
//初始化_OpenGL的显示模式
void OpenGL::InitMode(unsigned int Define)
{
	glutInitDisplayMode(Define);
}
//初始化_设置窗口客户区相对于桌面左上角的位置
void OpenGL::InitWinPos(int W, int H)
{
	glutInitWindowPosition(W, H);
}
//初始化_设置窗口的像素宽高(也就是客户区的宽高)
void OpenGL::InitWindSize(int Size_W, int Size_H)
{
	glutInitWindowSize(Size_W, Size_H);
}
//初始化_创建窗口，填写窗口标题栏的文字
void OpenGL::CreateWindows(const char *WindName)
{
	glutCreateWindow(WindName);
}
//初始化_设置的用于清除上一次绘制的颜色数据的颜色（相当于背景颜色）
void OpenGL::ClearColor(float R, float G, float B, float Alpha)//Alpha 为透明度
{
	glClearColor(R, G, B, Alpha);
}
//=======================================================
//初始化_设置绘制回调函数
void OpenGL::SerDrawCallback(void(*Func)())
{
	glutDisplayFunc(Func);
}
//初始化_当窗口大小和激活状态改变的时候会调用的函数
void OpenGL::WindSizeOractivation_Reshape(void(*Func)(int Width, int Height))
{
	glutReshapeFunc(Func);
}

//裁剪掉背面(3D中)
void OpenGL::EnableCullFace()
{
	glEnable(GL_CULL_FACE);//允许裁剪
	glCullFace(GL_BACK);//裁剪哪一面
}
//开启顶点数组,颜色数组,深度缓冲区,支持纹理2D贴图,UV数组坐标,开启颜色混合,开启模板缓冲区
void OpenGL::Enable_Varied__Buffer__(int Vertex, int Color, int DepthBuffer, int Texture2D, int UVCoordArray,int ColorBlend,int Template)
{
	if (Vertex == 1) { glEnableClientState(GL_VERTEX_ARRAY); }
	if (Color == 1) { glEnableClientState(GL_COLOR_ARRAY); }
	if (DepthBuffer == 1) { glEnable(GL_DEPTH_TEST); }
	if (Texture2D == 1) { glEnable(GL_TEXTURE_2D); }
	if (UVCoordArray == 1) { glEnableClientState(GL_TEXTURE_COORD_ARRAY); }
	if(ColorBlend == 1){ glEnable(GL_BLEND); }
	if(Template == 1)
	{
		glClearStencil(0);
		glEnable(GL_STENCIL_TEST);
		glStencilOp(GL_KEEP, GL_KEEP, GL_REPLACE);
	}
}
//创建灰度图地形
void OpenGL::CreateFromBmp(
	const char* BmpFile,//灰度图路径
	float H,//生成地形的最高Y值
	int Xwidth,//x方向格子数量
	int Zwidth,//z方向格子数量
	float Space)//表示单位格子的宽
{
	Map.CreateFromBMP(BmpFile, H, Xwidth, Zwidth, Space);
}
//绘制灰度图地形
void OpenGL::DrawMap()
{
	Map.DrawMap();
}

//普通键盘回调函数
void OpenGL::OrdinaryKeyDown(void(*KeyDown)(unsigned char Key, int Mouse_X, int Mouse_Y))
{
	glutKeyboardFunc(KeyDown);
}
void OpenGL::OrdinaryKeyUp(void(*KeyUp)(unsigned char Key, int Mouse_X, int Mouse_Y))
{
	glutKeyboardUpFunc(KeyUp);
}
//功能键回调函数
void OpenGL::SpecialKeyDown(void(*KeyDown)(int Key, int Mouse_X, int Mouse_Y))
{
	glutSpecialFunc(KeyDown);

}
void OpenGL::SpecialKeyUp(void(*KeyUp)(int Key, int Mouse_X, int Mouse_Y))
{
	glutSpecialUpFunc(KeyUp);
}
//鼠标回调函数
//鼠标按下/抬起
void OpenGL::MouseDown(void(*Mouse_Down)(int Button, int State, int Mouse_X, int Mouse_Y))
{
	//Button:
	//0 鼠标左键
	//1 鼠标中键
	//2 鼠标右键
	//3 鼠标滚轮向前
	//4 鼠标滚轮向后
	//State:0 按下,1 抬起
	glutMouseFunc(Mouse_Down);
}
//鼠标滑动
void OpenGL::MosueMove(void(*Mouse_Move)(int Mouse_X, int Mouse_Y))
{
	glutPassiveMotionFunc(Mouse_Move);
}
//鼠标拖拽
void OpenGL::MousePassive(void(*Mouse_Passive)(int Mouse_X, int Mouse_Y))
{
	glutMotionFunc(Mouse_Passive);
}
//计时器
void OpenGL::Timer_(unsigned int Millis, void(*Timer)(int Value), int Value)
{
	//多少毫秒调用函数，只调用一次
	glutTimerFunc(2000, Timer, Value);
}
//窗口处于空闲的时候调用
void OpenGL::WindIdle(void(*Indle)())
{
	glutIdleFunc(Indle);
}

//=====================================
//初始化_窗口循环
void OpenGL::MainWindLoop()
{
	glutMainLoop();
}