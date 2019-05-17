#pragma once
#include "stdafx.h"
#include <Windows.h>
#include <vector>
#pragma comment(lib,"Msimg32.lib")

#define GoBitmap GameBitmap::Interface()
class GameBitmap
{
public:
	static GameBitmap *Interface()
	{
		static GameBitmap BMP;
		return &BMP;
	}
	void InitBmp(HWND hWnd, int w = 816, int h = 638);
	void LoadBmp(const char *BmpName, int w, int h);//只有背景
	void LoadBmp(const char *BmpName, int w, int h, const char *Heroname, int wH, int hH);//有背景和英雄
	void LoadHero_Bmp(const char *BmpName, int w, int h);//加载只有英雄和它的宽高
	void LoadArms_Bmp(const char *Heroname, int w, int h);//加载武器位图和它的原来的宽高
	void Render_Hero_Arms_back_Bmp(int Mainx = 350, int Mainy = 250, int Mousex = 350, int Mousey = 250);//显示英雄与武器与背景，可能需要控制英雄和武器的坐标
	void RenderBmp();
	void RenderbackBmp();//只有背景图
	void RenderBmp(int Mainx, int Mainy);//控制英雄移动
	void Delete(HWND hWnd);

	//老师的位图方法
	//==============================================================
	void Init(HWND hWnd, HINSTANCE hInst);//初始化
	HDC GetDC() { return mHDC; }
	HDC GetMDC() { return mMDC; }
	void Begin();
	void End();//mdc到我们的hdc
	int Load_Bmp(const char *BmpName);
	int Load_Bmp(const char *BmpName, int w, int y);//重载一下，成为背景图片
	void DrawBmp1(int bmpid, int sx, int sy, int w, int h, int srcx, int srcy);//绘图风格1
	void DrawBmp2(int bmpid, int dx, int dy, int dw, int dh, int sx, int sy, int sw, int sh, DWORD color = RGB(255, 255, 255));//绘图风格2
	void ReleaseBmp(int bmpid);
	void SetWorldTransform(XFORM &m);
	//图形
	void DrawRectangle2(int cx, int cy, int w, int h, DWORD color1, DWORD color2);//边框颜色和填充颜色
	 //老师的字符串方法
	 //==============================================================
	int LoadFont(const char *FontName, int w, int h);//字体加载
	void DrawString_1(int Fontid, int sx, int sy, const char *string, int color = 0XFF00FF);//字符串显示风格1
private:
	GameBitmap() {}
	GameBitmap(const GameBitmap &data) {}
	HDC hdc, bdc, mdc;
	HBITMAP bmp, backbmp, Herobmp, Armsbmp;//空位图，背景图，英雄,武器位图
	int m_w, m_h;//位图实际的宽高
	int mw, mh;//武器的实际宽高
	int mh_w, mh_h; //实际窗口的宽高

	//老师的位图方法
	//==============================================================
	HDC mHDC, mMDC;//还是mdc到hdc
	RECT mRect;
	HWND mhWnd; //窗口句柄
	HINSTANCE mHinst; //实例句柄
	std::vector<HDC> mBmps;//位图列表
	int mWidth; //客户区的宽
	int mHeight; //客户区的高
	//老师的字符串方法
	//==============================================================
	std::vector<HFONT> mFonts;//字体表
};