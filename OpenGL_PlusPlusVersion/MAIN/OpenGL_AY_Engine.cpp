#include "OpenGL_AY_Engine.h"



ATROOT::ATROOT()
{

}
ATROOT::~ATROOT()
{
	delete[] m_BitMapRGBData;
	m_BitMapRGBData = NULL;
}
int ATROOT::LoadBitMap(const char *FileName, LPPIXCOLOR **BitMapData)
{
	FILE *pf = NULL;
	fopen_s(&pf, FileName, "rb");
	if (pf)
	{
		fread_s(&m_bf, sizeof(m_bf), sizeof(m_bf), 1, pf);
		if (m_bf.bfType != 0X4D42)
		{
			fclose(pf);
			pf = NULL;
			return 0;
		}
		fread_s(&m_bi, sizeof(m_bi), sizeof(m_bi), 1, pf);
		if (m_bi.biBitCount != 24)
		{
			fclose(pf);
			pf = NULL;
			return 0;
		}

		(*BitMapData) = new LPPIXCOLOR[m_bi.biHeight];

		int LineCount = m_bi.biSizeImage / m_bi.biHeight;
		int JumpCount = LineCount - m_bi.biWidth * sizeof(PIXCOLOR);

		for (int i = 0; i < m_bi.biHeight; i++)
		{
			(*BitMapData)[i] = new PIXCOLOR[m_bi.biWidth];

			fread_s((*BitMapData)[i], sizeof(PIXCOLOR) * m_bi.biWidth, sizeof(PIXCOLOR), m_bi.biWidth, pf);
			//一行一行的跳
			fseek(pf, JumpCount, SEEK_CUR);
		}

		fclose(pf);
		pf = NULL;
	}
	return 1;
}
int ATROOT::LoadBitMapRGBData(const char *FileName, LPPIXCOLOR **BitMapRGBData)
{
	FILE *pf = NULL;
	fopen_s(&pf, FileName, "rb");
	if (pf)
	{
		fread_s(&m_bf, sizeof(m_bf), sizeof(m_bf), 1, pf);
		if (m_bf.bfType != 0X4D42)
		{
			fclose(pf);
			pf = NULL;
			return 0;
		}
		fread_s(&m_bi, sizeof(m_bi), sizeof(m_bi), 1, pf);
		if (m_bi.biBitCount != 24)
		{
			fclose(pf);
			pf = NULL;
			return 0;
		}

		(*BitMapRGBData) = new LPPIXCOLOR[m_bi.biSizeImage / sizeof(PIXCOLOR)];
		fread_s((*BitMapRGBData), m_bi.biSizeImage, 1, m_bi.biSizeImage, pf);
		fclose(pf);
		pf = NULL;
	}
	return 1;
}
LPPIXCOLOR **ATROOT::LoadBitMapRGBData(const char *FileName)
{
	FILE *pf = NULL;
	fopen_s(&pf, FileName, "rb");
	if (pf)
	{
		fread_s(&m_bf, sizeof(m_bf), sizeof(m_bf), 1, pf);
		if (m_bf.bfType != 0X4D42)
		{
			fclose(pf);
			pf = NULL;
			return 0;
		}
		fread_s(&m_bi, sizeof(m_bi), sizeof(m_bi), 1, pf);
		if (m_bi.biBitCount != 24)
		{
			fclose(pf);
			pf = NULL;
			return 0;
		}
		m_BitMapRGBData = new LPPIXCOLOR[m_bi.biSizeImage / sizeof(PIXCOLOR)];
		fread_s(m_BitMapRGBData, m_bi.biSizeImage, 1, m_bi.biSizeImage, pf);
		fclose(pf);
		pf = NULL;
	}
	return &m_BitMapRGBData;
}
void ATROOT::DeleteBitMap(LPPIXCOLOR **BitMapData)
{
	if (BitMapData)
	{
		for (int i = 0; i < m_bi.biHeight; i++)
		{
			delete[](*BitMapData)[i];
			(*BitMapData)[i] = NULL;
		}
		delete[](*BitMapData);
		(*BitMapData) = NULL;
	}
}

void ATROOT::DrawRGB_DATA(float Begin_X, float Begin_Y, float Scale_X, float Scale_Y, float Width, float Height, unsigned int Format, unsigned int DataType, void *RGB)
{
	glRasterPos2f(Begin_X, Begin_Y);
	glPixelZoom(Scale_X, Scale_Y);
	glDrawPixels(
		Width, Height,
		Format, DataType,
		RGB);
}
void ATROOT::DrawRGB_DATA(ATATPOS2D Begin, ATATSCALE2D Scale, ATATCONTENTSIZE Size, unsigned int Format, unsigned int DataType, void *RGB)
{
	glRasterPos2f(Begin.Get_X(), Begin.Get_Y());
	glPixelZoom(Scale.Get_X(), Scale.Get_Y());
	glDrawPixels(
		Size.Get_Width(), Size.Get_Height(),
		Format, DataType,
		RGB);
}

LONG ATROOT::GetBitMapWidth()
{
	return m_bi.biWidth;
}
LONG ATROOT::GetBitMapHeight()
{
	return m_bi.biHeight;
}
LPPIXCOLOR **ATROOT::GetBitMapRGBData()
{
	return &m_BitMapRGBData;
}



//===============================================================
ATEngine *ATEngine::Interface()
{
	static ATEngine AT_Engine;
	return &AT_Engine;
}

void ATEngine::Init(DWORD Init, int *Argc, char **Argv)
{
	glutInit(Argc, Argv);
}

void ATEngine::InitMode(unsigned int Define)
{
	glutInitDisplayMode(Define);
}

void ATEngine::InitMode(unsigned int Define, int window_X, int window_Y, int Width, int Height)
{
	glutInitDisplayMode(Define);

	ATEngine::InitWindowPos(window_X, window_Y);
	ATEngine::InitWindowSize(Width, Height);

	ATEngine::InitCreateWindows();
}

void ATEngine::InitWindowPos(int window_X, int window_Y)
{
	glutInitWindowPosition(window_X, window_Y);
}

void ATEngine::InitWindowSize(int Width, int Height)
{
	glutInitWindowSize(Width, Height);
}

void ATEngine::InitCreateWindows(const char * WindowName)
{
	glutCreateWindow(WindowName);

	ATEngine::InitClearColor();
}

ATEngine::~ATEngine()
{

}
ATEngine::ATEngine()
{

}

void ATEngine::InitClearColor()
{
	glClearColor(
		ATVARIABLE->GetClearColor()->R,
		ATVARIABLE->GetClearColor()->G,
		ATVARIABLE->GetClearColor()->B,
		ATVARIABLE->GetClearColor()->Alpha);
}

//==================================================ATEngine_Variable
ATEngine_Variable::ATEngine_Variable()
{
	m_ClearColor.R = 0.0f;
	m_ClearColor.G = 0.0f;
	m_ClearColor.B = 0.0f;
	m_ClearColor.Alpha = 1.0f;

	m_glClear = GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT;

	m_EnablePoint = FALSE;

	m_Fovy = 90.0;
	m_Aspect = 1.0;
	m_ZNear = 0.3;
	m_ZFar = 1000.0;
}
ATEngine_Variable::~ATEngine_Variable()
{

}

ATEngine_Variable *ATEngine_Variable::Interface()
{
	static ATEngine_Variable ATEngineVariable;
	return &ATEngineVariable;
}

void ATEngine_Variable::SetClearColor(float R, float G, float B, float Alpha)
{
	m_ClearColor.R = R;
	m_ClearColor.G = G;
	m_ClearColor.B = B;
	m_ClearColor.Alpha = Alpha;
}
ATRGBA *ATEngine_Variable::GetClearColor()
{
	return &m_ClearColor;
}

void ATEngine_Variable::SetglClear(unsigned int glClear)
{
	m_glClear = glClear;
}
unsigned int *ATEngine_Variable::GetglClear()
{
	return &m_glClear;
}


//设置摄像机参数
void ATEngine_Variable::SetFAZZ(double Fovy, double Aspect, double ZNear, double ZFar)
{
	m_Fovy = Fovy;
	m_Aspect = Aspect;
	m_ZNear = ZNear;
	m_ZFar = ZFar;
}
double ATEngine_Variable::GetF()
{
	return m_Fovy;
}
double ATEngine_Variable::GetA()
{
	return m_Aspect;
}
double ATEngine_Variable::GetZ()
{
	return m_ZNear;
}
double ATEngine_Variable::Get_Z()
{
	return m_ZFar;
}

//==================================================

void ATEngine::ATENGINE_OnRuning(void(*MainDisplay)())
{
	glutDisplayFunc(MainDisplay);
}

void ATEngine::Console()
{
	//#ifndef _DEBUG
	//#pragma comment(linker,"/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")
	//#endif
}

void ATEngine::ATENGINE_Enable(unsigned int FUNCTION)
{
	glEnable(FUNCTION);
}

void ATEngine::ATENGINE_Disable(unsigned int FUNCTION)
{
	glDisable(FUNCTION);
}

void ATEngine::ATENGINE_EnableCilentState(unsigned int FUNCTION)
{
	glEnableClientState(FUNCTION);
}

void ATEngine::ATENGINE_CULLFACE(unsigned int CULLFACE)
{
	glCullFace(CULLFACE);
}

void ATEngine::ATENGINEMAIN_Loop()
{
	glutMainLoop();
}

void ATEngine::ATENGINE_Runing_Draw_Begin()
{
	//ATVARIABLE
	ATEngine::ATENGINE_Runing_Draw_glClear();
}

void ATEngine::DrawEnd()
{
	glEnd();
}

void ATEngine::ATENGINE_Runing_Draw_End()
{
	glFlush();
}

void ATEngine::ATENGINE_SWAPBUFFERS()
{
	glutSwapBuffers();
}

void ATEngine::ATENGINE_FPSDRAW(DWORD FPS)
{
	static DWORD LastTime = 0;
	DWORD CurTime = GetTickCount();

	if (CurTime - LastTime >= FPS)
	{
		ATENGINE->ATENGINE_RefreshDraw();
		//std::cout << "FPS = " << Fps << std::endl;
		LastTime = CurTime;
	}
}

void ATEngine::ATENGINE_Runing_Draw_glClear()
{
	glClear(*(ATVARIABLE->GetglClear()));
}

void ATEngine::Enable_Points()
{
	glBegin(GL_POINTS);
}

void ATEngine::ATENGINE_RefreshDraw()
{
	glutPostRedisplay();
}

//回调函数
//=================================================
void ATEngine::ATENGINE_OnWindowsChange(void(*OnWindowsChange)(int Width, int Height))
{
	glutReshapeFunc(OnWindowsChange);
}

void ATEngine::ATENGINE_OnOrdinaryKeyboardDownEvent(void(*OnOrdinaryKeyboardDownEvent)(unsigned char Key, int X, int Y))
{
	glutKeyboardFunc(OnOrdinaryKeyboardDownEvent);
}

void ATEngine::ATENGINE_OnOrdinaryKeyboardUpEvent(void(*OnOrdinaryKeyboardUpEvent)(unsigned char Key, int X, int Y))
{
	glutKeyboardUpFunc(OnOrdinaryKeyboardUpEvent);
}

void ATEngine::ATENGINE_OnSpecialKeyboardDownEvent(void(*OnSpecialKeyboardDownEvent)(int Key, int X, int Y))
{
	glutSpecialFunc(OnSpecialKeyboardDownEvent);
}

void ATEngine::ATENGINE_OnSpecialKeyboardUpEvent(void(*OnSpecialKeyboardUpEvent)(int Key, int X, int Y))
{
	glutSpecialUpFunc(OnSpecialKeyboardUpEvent);
}

void ATEngine::ATENGINE_OnMouseClickEvent(void(*OnMouseClickEvent)(int Button, int State, int Mouse_X, int Mouse_Y))
{
	glutMouseFunc(OnMouseClickEvent);
}

void ATEngine::ATENGINE_OnMouseMoveEvent(void(*OnMouseMoveEvent)(int Mouse_X, int Mouse_Y))
{
	glutPassiveMotionFunc(OnMouseMoveEvent);
}

void ATEngine::ATENGINE_OnMousePassiveEvent(void(*OnMousePassiveEvent)(int Mouse_X, int Mouse_Y))
{
	glutMotionFunc(OnMousePassiveEvent);
}

void ATEngine::ATENGINE_OnSetTimerEnd(unsigned int Millisecond, void(*OnTimerEnd)(int Timer_ID), int TimerID)
{
	glutTimerFunc(Millisecond, OnTimerEnd, TimerID);
}

void ATEngine::ATENGINE_PostRedisplayOnTimerBegin()
{
	glutPostRedisplay();
}

void ATEngine::ATENGINE_OnIdle(void(*OnIdle)())
{
	glutIdleFunc(OnIdle);
}

//=================================================矩阵

void ATEngine::ATENGINE_WindowsChangeMatrixModeAndOrtho2D(unsigned int MatrixMode, double Width, double Height, MATRIXMODE SourcePoint)
{
	ATEngine::ATENGINE_MatrixMode(MatrixMode);
	glViewport(0, 0, Width, Height);

	//0,0在中间 最大为1
	//glOrtho(-1,+1,-1,+1,0,1000);
	//0,0在中间 最大为 width / 2
	//glOrtho(-width / 2, width / 2, -height / 2, height / 2, 0, 1000);
	//0,0在左下角 最大为 width

	/*
							   最大的Y
									|
									|
	最小的X ==== ==|======最大的X
									|
									|
							   最小的Y
	*/

	//需要填写近远界面距离
	//gluOrtho2D();

	switch (SourcePoint)
	{
	case MATRIXMODE::CENTER:
	{
		glOrtho(-Width / 2, Width / 2, -Height / 2, Height / 2, 0, 1000);

	}; break;
	case MATRIXMODE::LEFTUP:
	{
		glOrtho(0, Width, Height, 0, 0, 1000);
	}; break;
	case MATRIXMODE::LEFTDOWN:
	{
		glOrtho(0, Width, 0, Height, 0, 1000);
	}; break;
	case MATRIXMODE::RIGHTUP:
	{
		glOrtho(Width, 0, Height, 0, 0, 1000);
	}; break;
	case MATRIXMODE::RIGHTDOWN:
	{
		glOrtho(Width, 0, 0, Height, 0, 1000);
	}; break;
	case MATRIXMODE::ZERO:
	{
		glOrtho(-1, +1, -1, +1, 0, 1000);
	}
	}
}

void ATEngine::ATENGINE_WindowsChangeMatrixModeAndOrtho3D(unsigned int MatrixMode, double Width, double Height, MATRIXMODE SourcePoint)
{
	ATEngine::ATENGINE_MatrixMode(MatrixMode);
	glViewport(0, 0, Width, Height);

	//透视投影
	//摄像机参数
	gluPerspective(
		ATVARIABLE->GetF(),//上下界面夹角
		ATVARIABLE->GetA(),//宽高比例
		ATVARIABLE->GetZ(),//近截面距离
		ATVARIABLE->Get_Z());//远截面距离
}

void ATEngine::SetCamer(double Fovy, double Aspect, double ZNear, double ZFar)
{
	ATVARIABLE->SetFAZZ(Fovy, Aspect, ZNear, ZFar);
}

void ATEngine::ATENGINE_MatrixMode(unsigned int MatrixMode)
{
	glMatrixMode(MatrixMode);
	glLoadIdentity();
}
//=====================================================
void ATEngine::EnableBase(unsigned int Base)
{
	glBegin(Base);
}

void ATEngine::Color3F(float R, float G, float B)
{
	glColor3f(R, G, B);
}

void ATEngine::Color3F(ATATRGB ATAT_RGB)
{
	glColor3f(ATAT_RGB.Get_R(), ATAT_RGB.Get_G(), ATAT_RGB.Get_B());
}

void ATEngine::Color3F(ATATRGBA ATAT_RGBA)
{
	glColor3f(ATAT_RGBA.Get_R(), ATAT_RGBA.Get_G(), ATAT_RGBA.Get_B());
}

void ATEngine::Color3UChar(unsigned char R, unsigned char G, unsigned char B)
{
	glColor3ub(R, G, B);
}

void ATEngine::Color3(unsigned char R, unsigned char G, unsigned char B)
{
	ATEngine::Color3UChar(R,G,B);
}

void ATEngine::Color4F(float R, float G, float B, float A)
{
	glColor4f(R, G, B, A);
}

void ATEngine::Color4F(ATATRGB ATAT_RGB)
{
	glColor4f(ATAT_RGB.Get_R(), ATAT_RGB.Get_G(), ATAT_RGB.Get_B(), 1.0f);
}

void ATEngine::Color4F(ATATRGBA ATAT_RGBA)
{
	glColor4f(ATAT_RGBA.Get_R(), ATAT_RGBA.Get_G(), ATAT_RGBA.Get_B(), ATAT_RGBA.Get_A());
}

void ATEngine::Color4UChar(unsigned char R, unsigned char G, unsigned char B, unsigned char A)
{
	glColor4ub(R,G,B,A);
}

void ATEngine::Color4(unsigned char R, unsigned char G, unsigned char B, unsigned char A)
{
	ATEngine::Color4UChar(R,G,B,A);
}

void ATEngine::Draw_Points(float X, float Y)
{
	glVertex2f(X, Y);
}
void ATEngine::Draw_Points(float R, float G, float B, float X, float Y)
{
	ATEngine::Color3F(ATATRGB(R, G, B));
	glVertex2f(X, Y);
}
void ATEngine::Draw_Points(float R, float G, float B, float A, int *Null, float X, float Y)
{
	ATEngine::Color4F(ATATRGBA(R, G, B, A));
	glVertex2f(X, Y);
}

void ATEngine::Draw_Points(float X, float Y, float Z)
{
	glVertex3f(X, Y, Z);
}
void ATEngine::Draw_Points(float R, float G, float B, float X, float Y, float Z)
{
	ATEngine::Color3F(ATATRGB(R, G, B));
	ATEngine::Draw_Points(X, Y, Z);
}
void ATEngine::Draw_Points(float R, float G, float B, float A, float X, float Y, float Z)
{
	ATEngine::Color4F(ATATRGBA(R, G, B, A));
	ATEngine::Draw_Points(X, Y, Z);
}

void ATEngine::Draw_Points(ATATPOS2D PointPos)
{
	glVertex2f(PointPos.Get_X(), PointPos.Get_Y());
}
void ATEngine::Draw_Points(ATATRGB ATAT_RGB, ATATPOS2D PointPos)
{
	ATEngine::Color3F(ATAT_RGB);
	ATEngine::Draw_Points(PointPos);
}
void ATEngine::Draw_Points(ATATRGBA ATAT_RGBA, ATATPOS2D PointPos)
{
	ATEngine::Color4F(ATAT_RGBA);
	ATEngine::Draw_Points(PointPos);
}

void ATEngine::Draw_Points(ATATPOS3D PointPos)
{
	glVertex3f(PointPos.Get_X(), PointPos.Get_Y(), PointPos.Get_Z());
}
void ATEngine::Draw_Points(ATATRGB ATAT_RGB, ATATPOS3D PointPos)
{
	ATEngine::Color3F(ATAT_RGB);
	ATEngine::Draw_Points(PointPos);
}
void ATEngine::Draw_Points(ATATRGBA ATAT_RGBA, ATATPOS3D PointPos)
{
	ATEngine::Color4F(ATAT_RGBA);
	ATEngine::Draw_Points(PointPos);
}


//Draw   Function
//============================================================
void ATEngine::CreateTriangle(float BeginPoint_X, float BeginPoint_Y, float CenterPoint_X, float CenterPoint_Y, float EndPoint_X, float EndPoint_Y)
{
	ATEngine::EnableBase(GL_TRIANGLES);
	ATEngine::Draw_Points(ATATPOS2D(BeginPoint_X, BeginPoint_Y));
	ATEngine::Draw_Points(ATATPOS2D(CenterPoint_X, CenterPoint_Y));
	ATEngine::Draw_Points(ATATPOS2D(EndPoint_X, EndPoint_Y));
}
void ATEngine::CreateTriangle(
	float R_B, float G_B, float B_B, float BeginPoint_X, float BeginPoint_Y,
	float R_C, float G_C, float B_C, float CenterPoint_X, float CenterPoint_Y,
	float R_E, float G_E, float B_E, float EndPoint_X, float EndPoint_Y)
{
	ATEngine::EnableBase(GL_TRIANGLES);
	ATEngine::Color3F(ATATRGB(R_B, G_B, B_B));
	ATEngine::Draw_Points(ATATPOS2D(BeginPoint_X, BeginPoint_Y));
	ATEngine::Color3F(ATATRGB(R_C, G_C, B_C));
	ATEngine::Draw_Points(ATATPOS2D(CenterPoint_X, CenterPoint_Y));
	ATEngine::Color3F(ATATRGB(R_E, G_E, B_E));
	ATEngine::Draw_Points(ATATPOS2D(EndPoint_X, EndPoint_Y));
}
void ATEngine::CreateTriangle(
	float R_B, float G_B, float B_B, float A_B, int *Null_B, float BeginPoint_X, float BeginPoint_Y,
	float R_C, float G_C, float B_C, float A_C, int *Null_C, float CenterPoint_X, float CenterPoint_Y,
	float R_E, float G_E, float B_E, float A_E, int *Null_E, float EndPoint_X, float EndPoint_Y)
{
	ATEngine::EnableBase(GL_TRIANGLES);
	ATEngine::Color4F(ATATRGBA(R_B, G_B, B_B, A_B));
	ATEngine::Draw_Points(ATATPOS2D(BeginPoint_X, BeginPoint_Y));
	ATEngine::Color4F(ATATRGBA(R_C, G_C, B_C, A_C));
	ATEngine::Draw_Points(ATATPOS2D(CenterPoint_X, CenterPoint_Y));
	ATEngine::Color4F(ATATRGBA(R_E, G_E, B_E, A_E));
	ATEngine::Draw_Points(ATATPOS2D(EndPoint_X, EndPoint_Y));
}
void ATEngine::CreateTriangle(
	float BeginPoint_X, float BeginPoint_Y, float BeginPoint_Z,
	float CenterPoint_X, float CenterPoint_Y, float CenterPoint_Z,
	float EndPoint_X, float EndPoint_Y, float EndPoint_Z)
{
	ATEngine::EnableBase(GL_TRIANGLES);
	ATEngine::Draw_Points(ATATPOS3D(BeginPoint_X, BeginPoint_Y, BeginPoint_Z));
	ATEngine::Draw_Points(ATATPOS3D(CenterPoint_X, CenterPoint_Y, CenterPoint_Z));
	ATEngine::Draw_Points(ATATPOS3D(EndPoint_X, EndPoint_Y, EndPoint_Z));
}
void ATEngine::CreateTriangle(
	float R_B, float G_B, float B_B, float BeginPoint_X, float BeginPoint_Y, float BeginPoint_Z,
	float R_C, float G_C, float B_C, float CenterPoint_X, float CenterPoint_Y, float CenterPoint_Z,
	float R_E, float G_E, float B_E, float EndPoint_X, float EndPoint_Y, float EndPoint_Z)
{
	ATEngine::EnableBase(GL_TRIANGLES);
	ATEngine::Color3F(ATATRGB(R_B, G_B, B_B));
	ATEngine::Draw_Points(ATATPOS3D(BeginPoint_X, BeginPoint_Y, BeginPoint_Z));
	ATEngine::Color3F(ATATRGB(R_C, G_C, B_C));
	ATEngine::Draw_Points(ATATPOS3D(CenterPoint_X, CenterPoint_Y, CenterPoint_Z));
	ATEngine::Color3F(ATATRGB(R_E, G_E, B_E));
	ATEngine::Draw_Points(ATATPOS3D(EndPoint_X, EndPoint_Y, EndPoint_Z));
}
void ATEngine::CreateTriangle(
	float R_B, float G_B, float B_B, float A_B, float BeginPoint_X, float BeginPoint_Y, float BeginPoint_Z,
	float R_C, float G_C, float B_C, float A_C, float CenterPoint_X, float CenterPoint_Y, float CenterPoint_Z,
	float R_E, float G_E, float B_E, float A_E, float EndPoint_X, float EndPoint_Y, float EndPoint_Z)
{
	ATEngine::EnableBase(GL_TRIANGLES);
	ATEngine::Color4F(ATATRGBA(R_B, G_B, B_B, A_B));
	ATEngine::Draw_Points(ATATPOS3D(BeginPoint_X, BeginPoint_Y, BeginPoint_Z));
	ATEngine::Color4F(ATATRGBA(R_C, G_C, B_C, A_C));
	ATEngine::Draw_Points(ATATPOS3D(CenterPoint_X, CenterPoint_Y, CenterPoint_Z));
	ATEngine::Color4F(ATATRGBA(R_E, G_E, B_E, A_E));
	ATEngine::Draw_Points(ATATPOS3D(EndPoint_X, EndPoint_Y, EndPoint_Z));
}


void ATEngine::CreateTriangle(ATATPOS2D BeginPoint, ATATPOS2D CenterPoint, ATATPOS2D EndPoint)
{
	ATEngine::EnableBase(GL_TRIANGLES);
	ATEngine::Draw_Points(BeginPoint);
	ATEngine::Draw_Points(CenterPoint);
	ATEngine::Draw_Points(EndPoint);
}
void ATEngine::CreateTriangle(
	ATATRGB ATAT_RGB_B, ATATPOS2D BeginPoint,
	ATATRGB ATAT_RGB_C, ATATPOS2D CenterPoint,
	ATATRGB ATAT_RGB_E, ATATPOS2D EndPoint)
{
	ATEngine::EnableBase(GL_TRIANGLES);
	ATEngine::Color3F(ATAT_RGB_B);
	ATEngine::Draw_Points(BeginPoint);
	ATEngine::Color3F(ATAT_RGB_C);
	ATEngine::Draw_Points(CenterPoint);
	ATEngine::Color3F(ATAT_RGB_E);
	ATEngine::Draw_Points(EndPoint);
}
void ATEngine::CreateTriangle(
	ATATRGBA ATAT_RGBA_B, ATATPOS2D BeginPoint,
	ATATRGBA ATAT_RGBA_C, ATATPOS2D CenterPoint,
	ATATRGBA ATAT_RGBA_E, ATATPOS2D EndPoint)
{
	ATEngine::EnableBase(GL_TRIANGLES);
	ATEngine::Color4F(ATAT_RGBA_B);
	ATEngine::Draw_Points(BeginPoint);
	ATEngine::Color4F(ATAT_RGBA_C);
	ATEngine::Draw_Points(CenterPoint);
	ATEngine::Color4F(ATAT_RGBA_E);
	ATEngine::Draw_Points(EndPoint);
}

void ATEngine::CreateTriangle(ATATPOS3D BeginPoint, ATATPOS3D CenterPoint, ATATPOS3D EndPoint)
{
	ATEngine::EnableBase(GL_TRIANGLES);
	ATEngine::Draw_Points(BeginPoint);
	ATEngine::Draw_Points(CenterPoint);
	ATEngine::Draw_Points(EndPoint);
}
void ATEngine::CreateTriangle(
	ATATRGB ATAT_RGB_B, ATATPOS3D BeginPoint,
	ATATRGB ATAT_RGB_C, ATATPOS3D CenterPoint,
	ATATRGB ATAT_RGB_E, ATATPOS3D EndPoint)
{
	ATEngine::EnableBase(GL_TRIANGLES);
	ATEngine::Color3F(ATAT_RGB_B);
	ATEngine::Draw_Points(BeginPoint);
	ATEngine::Color3F(ATAT_RGB_C);
	ATEngine::Draw_Points(CenterPoint);
	ATEngine::Color3F(ATAT_RGB_E);
	ATEngine::Draw_Points(EndPoint);
}
void ATEngine::CreateTriangle(
	ATATRGBA ATAT_RGBA_B, ATATPOS3D BeginPoint,
	ATATRGBA ATAT_RGBA_C, ATATPOS3D CenterPoint,
	ATATRGBA ATAT_RGBA_E, ATATPOS3D EndPoint)
{
	ATEngine::EnableBase(GL_TRIANGLES);
	ATEngine::Color4F(ATAT_RGBA_B);
	ATEngine::Draw_Points(BeginPoint);
	ATEngine::Color4F(ATAT_RGBA_C);
	ATEngine::Draw_Points(CenterPoint);
	ATEngine::Color4F(ATAT_RGBA_E);
	ATEngine::Draw_Points(EndPoint);
}


//=============================================================四边形
void ATEngine::CreateQuadrangle(
	float BeginPoint_X, float BeginPoint_Y,
	float CenterPoint_X_0, float CenterPoint_Y_0,
	float CenterPoint_X_1, float CenterPoint_Y_1,
	float EndPoint_X, float EndPoint_Y)
{
	ATEngine::EnableBase(GL_QUADS);
	ATEngine::Draw_Points(BeginPoint_X, BeginPoint_Y);
	ATEngine::Draw_Points(CenterPoint_X_0, CenterPoint_Y_0);
	ATEngine::Draw_Points(CenterPoint_X_1, CenterPoint_Y_1);
	ATEngine::Draw_Points(EndPoint_X, EndPoint_Y);
}
void ATEngine::CreateQuadrangle(
	float R_B, float G_B, float B_B, float BeginPoint_X, float BeginPoint_Y,
	float R_C_0, float G_C_0, float B_C_0, float CenterPoint_X_0, float CenterPoint_Y_0,
	float R_C_1, float G_C_1, float B_C_1, float CenterPoint_X_1, float CenterPoint_Y_1,
	float R_E, float G_E, float B_E, float EndPoint_X, float EndPoint_Y)
{
	ATEngine::EnableBase(GL_QUADS);
	ATEngine::Color3F(R_B, G_B, B_B);
	ATEngine::Draw_Points(BeginPoint_X, BeginPoint_Y);
	ATEngine::Color3F(R_C_0, G_C_0, B_C_0);
	ATEngine::Draw_Points(CenterPoint_X_0, CenterPoint_Y_0);
	ATEngine::Color3F(R_C_1, G_C_1, B_C_1);
	ATEngine::Draw_Points(CenterPoint_X_1, CenterPoint_Y_1);
	ATEngine::Color3F(R_E, G_E, B_E);
	ATEngine::Draw_Points(EndPoint_X, EndPoint_Y);
}
//填0隔开重载
void ATEngine::CreateQuadrangle(
	float R_B, float G_B, float B_B, float A_B, int *Null_B, float BeginPoint_X, float BeginPoint_Y,
	float R_C_0, float G_C_0, float B_C_0, float A_C_0, int *Null_C_0, float CenterPoint_X_0, float CenterPoint_Y_0,
	float R_C_1, float G_C_1, float B_C_1, float A_C_1, int *Null_C_1, float CenterPoint_X_1, float CenterPoint_Y_1,
	float R_E, float G_E, float B_E, float A_E, int *Null_E, float EndPoint_X, float EndPoint_Y)
{
	ATEngine::EnableBase(GL_QUADS);
	ATEngine::Color4F(R_B, G_B, B_B, A_B);
	ATEngine::Draw_Points(BeginPoint_X, BeginPoint_Y);
	ATEngine::Color4F(R_C_0, G_C_0, B_C_0, A_C_0);
	ATEngine::Draw_Points(CenterPoint_X_0, CenterPoint_Y_0);
	ATEngine::Color4F(R_C_1, G_C_1, B_C_1, A_C_1);
	ATEngine::Draw_Points(CenterPoint_X_1, CenterPoint_Y_1);
	ATEngine::Color4F(R_E, G_E, B_E, A_E);
	ATEngine::Draw_Points(EndPoint_X, EndPoint_Y);
}

void ATEngine::CreateQuadrangle(
	float BeginPoint_X, float BeginPoint_Y, float BeginPoint_Z,
	float CenterPoint_X_0, float CenterPoint_Y_0, float CenterPoint_Z_0,
	float CenterPoint_X_1, float CenterPoint_Y_1, float CenterPoint_Z_1,
	float EndPoint_X, float EndPoint_Y, float EndPoint_Z)
{
	ATEngine::EnableBase(GL_QUADS);
	ATEngine::Draw_Points(BeginPoint_X, BeginPoint_Y, BeginPoint_Z);
	ATEngine::Draw_Points(CenterPoint_X_0, CenterPoint_Y_0, CenterPoint_Z_0);
	ATEngine::Draw_Points(CenterPoint_X_1, CenterPoint_Y_1, CenterPoint_Z_1);
	ATEngine::Draw_Points(EndPoint_X, EndPoint_Y, EndPoint_Z);
}
void ATEngine::CreateQuadrangle(
	float R_B, float G_B, float B_B, float BeginPoint_X, float BeginPoint_Y, float BeginPoint_Z,
	float R_C_0, float G_C_0, float B_C_0, float CenterPoint_X_0, float CenterPoint_Y_0, float CenterPoint_Z_0,
	float R_C_1, float G_C_1, float B_C_1, float CenterPoint_X_1, float CenterPoint_Y_1, float CenterPoint_Z_1,
	float R_E, float G_E, float B_E, float EndPoint_X, float EndPoint_Y, float EndPoint_Z)
{
	ATEngine::EnableBase(GL_QUADS);
	ATEngine::Color3F(R_B, G_B, B_B);
	ATEngine::Draw_Points(BeginPoint_X, BeginPoint_Y, BeginPoint_Z);
	ATEngine::Color3F(R_C_0, G_C_0, B_C_0);
	ATEngine::Draw_Points(CenterPoint_X_0, CenterPoint_Y_0, CenterPoint_Z_0);
	ATEngine::Color3F(R_C_1, G_C_1, B_C_1);
	ATEngine::Draw_Points(CenterPoint_X_1, CenterPoint_Y_1, CenterPoint_Z_1);
	ATEngine::Color3F(R_E, G_E, B_E);
	ATEngine::Draw_Points(EndPoint_X, EndPoint_Y, EndPoint_Z);
}
void ATEngine::CreateQuadrangle(
	float R_B, float G_B, float B_B, float A_B, float BeginPoint_X, float BeginPoint_Y, float BeginPoint_Z,
	float R_C_0, float G_C_0, float B_C_0, float A_C_0, float CenterPoint_X_0, float CenterPoint_Y_0, float CenterPoint_Z_0,
	float R_C_1, float G_C_1, float B_C_1, float A_C_1, float CenterPoint_X_1, float CenterPoint_Y_1, float CenterPoint_Z_1,
	float R_E, float G_E, float B_E, float A_E, float EndPoint_X, float EndPoint_Y, float EndPoint_Z)
{
	ATEngine::EnableBase(GL_QUADS);
	ATEngine::Color4F(R_B, G_B, B_B, A_B);
	ATEngine::Draw_Points(BeginPoint_X, BeginPoint_Y, BeginPoint_Z);
	ATEngine::Color4F(R_C_0, G_C_0, B_C_0, A_C_0);
	ATEngine::Draw_Points(CenterPoint_X_0, CenterPoint_Y_0, CenterPoint_Z_0);
	ATEngine::Color4F(R_C_1, G_C_1, B_C_1, A_C_1);
	ATEngine::Draw_Points(CenterPoint_X_1, CenterPoint_Y_1, CenterPoint_Z_1);
	ATEngine::Color4F(R_E, G_E, B_E, A_E);
	ATEngine::Draw_Points(EndPoint_X, EndPoint_Y, EndPoint_Z);
}


void ATEngine::CreateQuadrangle(ATATPOS2D BeginPoint, ATATPOS2D CenterPoint_0, ATATPOS2D CenterPoint_1, ATATPOS2D EndPoint)
{
	ATEngine::EnableBase(GL_QUADS);
	ATEngine::Draw_Points(BeginPoint);
	ATEngine::Draw_Points(CenterPoint_0);
	ATEngine::Draw_Points(CenterPoint_1);
	ATEngine::Draw_Points(EndPoint);
}
void ATEngine::CreateQuadrangle(
	ATATRGB ATAT_RGB_B, ATATPOS2D BeginPoint,
	ATATRGB ATAT_RGB_C_0, ATATPOS2D CenterPoint_0,
	ATATRGB ATAT_RGB_C_1, ATATPOS2D CenterPoint_1,
	ATATRGB ATAT_RGB_E, ATATPOS2D EndPoint)
{
	ATEngine::EnableBase(GL_QUADS);
	ATEngine::Color3F(ATAT_RGB_B);
	ATEngine::Draw_Points(BeginPoint);
	ATEngine::Color3F(ATAT_RGB_C_0);
	ATEngine::Draw_Points(CenterPoint_0);
	ATEngine::Color3F(ATAT_RGB_C_1);
	ATEngine::Draw_Points(CenterPoint_1);
	ATEngine::Color3F(ATAT_RGB_E);
	ATEngine::Draw_Points(EndPoint);
}
void ATEngine::CreateQuadrangle(
	ATATRGBA ATAT_RGB_B, ATATPOS2D BeginPoint,
	ATATRGBA ATAT_RGB_C_0, ATATPOS2D CenterPoint_0,
	ATATRGBA ATAT_RGB_C_1, ATATPOS2D CenterPoint_1,
	ATATRGBA ATAT_RGB_E, ATATPOS2D EndPoint)
{
	ATEngine::EnableBase(GL_QUADS);
	ATEngine::Color4F(ATAT_RGB_B);
	ATEngine::Draw_Points(BeginPoint);
	ATEngine::Color4F(ATAT_RGB_C_0);
	ATEngine::Draw_Points(CenterPoint_0);
	ATEngine::Color4F(ATAT_RGB_C_1);
	ATEngine::Draw_Points(CenterPoint_1);
	ATEngine::Color4F(ATAT_RGB_E);
	ATEngine::Draw_Points(EndPoint);
}
void ATEngine::CreateQuadrangle(ATATPOS3D BeginPoint, ATATPOS3D CenterPoint_0, ATATPOS3D CenterPoint_1, ATATPOS3D EndPoint)
{
	ATEngine::EnableBase(GL_QUADS);
	ATEngine::Draw_Points(BeginPoint);
	ATEngine::Draw_Points(CenterPoint_0);
	ATEngine::Draw_Points(CenterPoint_1);
	ATEngine::Draw_Points(EndPoint);
}
void ATEngine::CreateQuadrangle(
	ATATRGB ATAT_RGB_B, ATATPOS3D BeginPoint,
	ATATRGB ATAT_RGB_C_0, ATATPOS3D CenterPoint_0,
	ATATRGB ATAT_RGB_C_1, ATATPOS3D CenterPoint_1,
	ATATRGB ATAT_RGB_E, ATATPOS3D EndPoint)
{
	ATEngine::EnableBase(GL_QUADS);
	ATEngine::Color3F(ATAT_RGB_B);
	ATEngine::Draw_Points(BeginPoint);
	ATEngine::Color3F(ATAT_RGB_C_0);
	ATEngine::Draw_Points(CenterPoint_0);
	ATEngine::Color3F(ATAT_RGB_C_1);
	ATEngine::Draw_Points(CenterPoint_1);
	ATEngine::Color3F(ATAT_RGB_E);
	ATEngine::Draw_Points(EndPoint);
}
void ATEngine::CreateQuadrangle(
	ATATRGBA ATAT_RGB_B, ATATPOS3D BeginPoint,
	ATATRGBA ATAT_RGB_C_0, ATATPOS3D CenterPoint_0,
	ATATRGBA ATAT_RGB_C_1, ATATPOS3D CenterPoint_1,
	ATATRGBA ATAT_RGB_E, ATATPOS3D EndPoint)
{
	ATEngine::EnableBase(GL_QUADS);
	ATEngine::Color4F(ATAT_RGB_B);
	ATEngine::Draw_Points(BeginPoint);
	ATEngine::Color4F(ATAT_RGB_C_0);
	ATEngine::Draw_Points(CenterPoint_0);
	ATEngine::Color4F(ATAT_RGB_C_1);
	ATEngine::Draw_Points(CenterPoint_1);
	ATEngine::Color4F(ATAT_RGB_E);
	ATEngine::Draw_Points(EndPoint);
}


//=============================================================绘图列表
unsigned int ATEngine::CreateDrawList(unsigned int Number)
{
	int ID = glGenLists(Number);
	glNewList(ID, GL_COMPILE);
	return ID;
}
unsigned int ATEngine::CreateDrawListAndDraw(unsigned int Number)
{
	int ID = glGenLists(Number);
	glNewList(ID, GL_COMPILE_AND_EXECUTE);
	return ID;
}
void ATEngine::DrawDrawList(unsigned int DrawListID)
{
	glCallList(DrawListID);
}
void ATEngine::DrawDrawList_s(unsigned int DrawListIDNum, unsigned int ArrType, unsigned int *Arr)
{
	glCallLists(DrawListIDNum, ArrType, Arr);
}
void ATEngine::EndDrawList()
{
	glEndList();
}
void ATEngine::DeleteDrawList(unsigned int DrawListID, unsigned int Number)
{
	glDeleteLists(DrawListID, Number);
}

//===============================================================平移,旋转
void ATEngine::Translate(float X, float Y, float Z)
{
	glTranslatef(X, Y, Z);
}
void ATEngine::Translate(ATATPOS3D ATATPos3D)
{
	glTranslatef(ATATPos3D.Get_X(), ATATPos3D.Get_Y(), ATATPos3D.Get_Z());
}
void ATEngine::Rotate(float Angle, float X, float Y, float Z)
{
	glRotatef(Angle, X, Y, Z);
}
void ATEngine::Rotate(float Angle, ATATPOS3D ATATPos3D)
{
	glRotatef(Angle, ATATPos3D.Get_X(), ATATPos3D.Get_Y(), ATATPos3D.Get_Z());
}