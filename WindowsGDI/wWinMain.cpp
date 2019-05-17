#include "Game.h"

//===========================================
Game *GameObj = NULL;
//===========================================
//回调函数声明
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
int __stdcall wWinMain(HINSTANCE hInstance,//窗口的实例句柄
	HINSTANCE hPrevInstance,//前一个实例句柄
	LPTSTR    lpCmdLine,//命令行
	int       nCmdShow)//显示方式
{
	GameObj = new Game();
	//注册窗口类
	WNDCLASSEX wcex;
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WndProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = NULL;
	wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = NULL;
	wcex.lpszClassName = L"GameWindow";
	wcex.hIconSm = NULL;
	RegisterClassEx(&wcex);

	//客户区大小
	RECT wndrc = { 0, 0, 800, 600 };
	AdjustWindowRect(&wndrc, WS_OVERLAPPED | WS_CAPTION | WS_THICKFRAME | WS_SYSMENU, FALSE);

	int screen_w = GetSystemMetrics(SM_CXSCREEN);
	int screen_h = GetSystemMetrics(SM_CYSCREEN);
	int wnd_w = wndrc.right - wndrc.left;
	int wnd_h = wndrc.bottom - wndrc.top;

	//创建窗口
	HWND hWnd = CreateWindow(
		L"GameWindow", //窗口类名
		L"Game", //窗口的标题
		WS_OVERLAPPED | WS_CAPTION | WS_THICKFRAME | WS_SYSMENU,//窗口风格
		(screen_w - wnd_w) / 2, //窗口显示到桌面的坐标x
		(screen_h - wnd_h) / 2, //窗口显示到桌面的坐标y  (screen_h - wnd_h) / 2 - 2
		wnd_w, //整个窗口的宽，包括客户区
		wnd_h, //整个窗口的高，包括客户区
		NULL, //父窗口句柄，填0表示父窗口是桌面
		NULL, //菜单句柄
		hInstance, //
		NULL);
	if (!hWnd)//如果窗口不等于NULL说明创建窗口成功
	{
		return FALSE;
	}
	ShowWindow(hWnd, nCmdShow);//显示窗口
	UpdateWindow(hWnd);

	//加载的代码放这儿(1)HDC hdc = GetDC(hWnd);释放	ReleaseDC(hWnd, hdc);
	//========================================================
	HDC hdc = GetDC(hWnd);
	GameObj->InitGame(hdc, hWnd, hInstance);
	//===================================================

	//处理消息循环
	MSG msg;
	// 主消息循环:
	ZeroMemory(&msg, sizeof(msg));
	while (msg.message != WM_QUIT)
	{
		if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		else
		{
			//游戏逻辑和渲染,在窗口显示之后会不动，所以逻辑写这里才可以(1)
			//===================================================
			GameObj->RunGame(hdc, hWnd, hInstance);
			//===================================================
			//InvalidateRect(hWnd, NULL, FALSE);//刷新
		}
	}
	//释放资源放这
	//===============================================
	GameObj->GameOver();
	delete GameObj;
	//===============================================
	return (int)msg.wParam;
}
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	MouseMessage stame;
	memset(&stame, 0, sizeof(stame));
	KeyMessage Stame;
	memset(&Stame, 0, sizeof(Stame));
	HDC hdc;
	PAINTSTRUCT ps;//绘制环境信息
	switch (message)
	{
	case WM_PAINT://第一次窗口创建的时候
	{
		hdc = BeginPaint(hWnd, &ps);
		// TODO: 在此添加任意绘图代码...(2)
		//===================================================

		//===================================================
		EndPaint(hWnd, &ps);
	}; break;
	case WM_CREATE://这里可以加载资源，图片声音，子窗口等(2)
	{
		//============================================================
		//============================================================
	}; break;
	case WM_KEYDOWN://按键方向控制
	{
		Stame.Which = wParam;
		Stame.State = 1;
		GameObj->GameKeyMessage(Stame);
	}; break;
	case WM_KEYUP://按键抬起
	{
		Stame.Which = wParam;
		Stame.State = 0;
		GameObj->GameKeyMessage(Stame);
	}; break;
	case WM_LBUTTONDOWN: //鼠标左键按下
	{
		//MessageBox(hWnd, L"鼠标左键按下", L"鼠标消息", 0);
		stame.Which = 1;
		stame.State = 1;
		stame.x = LOWORD(lParam);
		stame.y = HIWORD(lParam);
		GameObj->GameMouseMessage(stame);

	}; break;
	case WM_LBUTTONUP://鼠标左键抬起
	{
		//MessageBox(hWnd, L"鼠标左键抬起", L"鼠标消息", 0);
		stame.Which = 1;
		stame.State = 0;
		stame.x = LOWORD(lParam);
		stame.y = HIWORD(lParam);
		GameObj->GameMouseMessage(stame);
	}; break;
	case WM_LBUTTONDBLCLK://鼠标左键双击
	{}; break;
	case WM_RBUTTONDOWN://鼠标右键按下
	{}; break;
	case WM_RBUTTONUP://鼠标右键抬起
	{}; break;
	case WM_MOUSEMOVE://鼠标移动消息
	{
		//stame.x = LOWORD(lParam);
		//stame.y = HIWORD(lParam);
		//GameObj->GameMouseMessage(stame);
	}; break;
	case WM_MOUSEWHEEL://鼠标滚轮消息
	{}; break;
	case WM_SIZE: {}; break;//窗口大小改变消息
	case WM_DESTROY://这里可以清理内存、释放资源等
	{
		//============================================================

		//============================================================
		PostQuitMessage(0);
	}; break;
	default:return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}


