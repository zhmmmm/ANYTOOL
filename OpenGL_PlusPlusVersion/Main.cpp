#include "MAIN/OpenGL_AY_Engine.h"
#include "Scene.h"



#define Main main



// ATENGINE
// ATVARIABLE

LPPIXCOLOR *RGBData = NULL;
Sprite *S = new Sprite();

Scene g_Object;

void MainDisplay();
void MainInit();


void OnWindowsChange(int width, int height)
{
	std::cout << "刷新 OnWindowsChange" << std::endl;
	std::cout << width << " " << height << std::endl;
	ATENGINE->ATENGINE_WindowsChangeMatrixModeAndOrtho3D(GL_PROJECTION,
		width, height,
		MATRIXMODE::CENTER);
}
//键盘
void OnOrdinaryKeyboardDown(unsigned char Key, int X, int Y)
{
	//std::cout << "普通按下！" << Key << " X = " << X << " Y = " << Y << std::endl;
	//if (Key == '\r')
	//{
	//	exit(0);
	//}
	g_Object.OnOrdinaryKeyboardDownEvent(Key, X, Y);
}
void OnOrdinaryKeyboardUp(unsigned char Key, int X, int Y)
{
	//std::cout << "普通抬起！" << Key << " X = " << X << " Y = " << Y << std::endl;
	g_Object.OnOrdinaryKeyboardUpEvent(Key, X, Y);
}
void OnSpecialKeyboardDown(int Key, int X, int Y)
{
	//std::cout << "功能按下！" << Key << " X = " << X << " Y = " << Y << std::endl;
	g_Object.OnSpecialKeyboardDownEvent(Key, X, Y);
}
void OnSpecialKeyboardUp(int Key, int X, int Y)
{
	//std::cout << "功能抬起！" <<Key<<" X = "<<X<<" Y = "<<Y<< std::endl;
	g_Object.OnSpecialKeyboardUpEvent(Key, X, Y);
}

//鼠标
void OnMouseClickEvent(int Button, int State, int X, int Y)
{
	//std::cout << "Button =" << Button << " State = " << State << " X = " << X << " Y = " << Y << std::endl;
	g_Object.OnMouseClickEvent(Button, State, X, Y);
}
void OnMouseMoveEvent(int Mouse_X, int Mouse_Y)
{
	//std::cout << "鼠标移动 " << "X = " << Mouse_X << " Y = " << Mouse_Y << std::endl;
	g_Object.OnMouseMoveEvent(Mouse_X, Mouse_Y);
}
void OnMousePassiveEvent(int Mouse_X, int Mouse_Y)
{
	//std::cout << "鼠标拖拽 " << "X = " << Mouse_X << " Y = " << Mouse_Y << std::endl;
	g_Object.OnMousePassiveEvent(Mouse_X, Mouse_Y);
}

void OnIdle()
{
	//std::cout << "窗口空闲刷新" << std::endl;
	//ATENGINE->ATENGINE_RefreshDraw();
	ATENGINE->ATENGINE_FPSDRAW(1);
}

int Main(int argc, char **argv)
{

	//ATVARIABLE->SetPoint(TRUE);
	//ATVARIABLE->SetPointPosition(0.5,0.5);

	MainInit();
	ATENGINE->Init(AT_INITOPENGL, &argc, argv);
	ATENGINE->InitMode(GLUT_DOUBLE | GLUT_RGBA,
		g_Object.m_Windows_X, g_Object.m_Windows_Y,
		g_Object.m_WindowsWidth, g_Object.m_WindowsHeight);
	ATENGINE_MAINDRAW(MainDisplay);
	ATENGINE_ONWINDOWSCHANGE(OnWindowsChange);
	ATENGINE_ONORDINARYKEYBOARDDOWN(OnOrdinaryKeyboardDown);
	ATENGINE_ONSPECIAKEYBOARDDOWN(OnSpecialKeyboardDown);
	ATENGINE_ONORDINARYKEYBOARDUP(OnOrdinaryKeyboardUp);
	ATENGINE_ONSPECIAKEYBOARDUP(OnSpecialKeyboardUp);
	ATENGINE_ONMOUSECILCKEVENT(OnMouseClickEvent);
	ATENGINE_ONMOUSEMOVEEVENT(OnMouseMoveEvent);
	ATENGINE_ONMOUSEPASSIVEEVENT(OnMousePassiveEvent);
	ATENGINE_ONIDLE(OnIdle);

	ATENGINE->ATENGINE_Enable();
	ATENGINE->ATENGINE_CULLFACE();

	ATENGINE->ATENGINEMAIN_Loop();

	g_Object.End();

	system("pause");
	return 0;
}

void MainInit()
{
	g_Object.Start();

	int Ending = 0;
}
void MainDisplay()
{
	ATENGINE->ATENGINE_Runing_Draw_Begin();


	g_Object.Update();



	ATENGINE->ATENGINE_Runing_Draw_End();
	ATENGINE->ATENGINE_SWAPBUFFERS();
}