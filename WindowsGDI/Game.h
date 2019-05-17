#pragma once
#include <iostream>
#include <Windows.h>


struct KeyMessage//按键消息
{
	int Which;//哪一个键
	int State;//按下还是抬起
};
struct MouseMessage//鼠标消息
{
	int Which;//鼠标哪一个键
	int State;//按下还是抬起
	int x;//鼠标坐标
	int y;
};
struct COOR
{
	int x;
	int y;
};

class Game
{

public:
	Game()
	{

	}
	void InitPiece()
	{

	}
	void InitGame(HDC hdc, HWND hWnd, HINSTANCE hInst)
	{

	}
	void RenderGame(HDC hdc, HWND hWnd, HINSTANCE hInst)
	{

	}
	void GameLogic_Updata(HDC hdc, HWND hWnd, HINSTANCE hInst)
	{
		
	}
	void RunGame(HDC hdc, HWND hWnd, HINSTANCE hInst)
	{
		static DWORD lasttime = 0;//静态的局部变量
		DWORD curtime = GetTickCount();
		if (curtime - lasttime >= 60)
		{

			lasttime = curtime;
		}

		//这里是直接绘制到hdc上的

	}
	void GameOver(){}
	void GameKeyMessage(KeyMessage Key)
	{

	}
	void GameMouseMessage(MouseMessage MouseMsge)
	{

	}

	~Game()
	{

	}
};