#include "stdafx.h"
#include "Bitbmp.h"
#include "Matrix3.h"

void GameBitmap::InitBmp(HWND hWnd, int w, int h)
{
	mh_w = w;
	mh_h = h;
	hdc = ::GetDC(hWnd); //得到和外部一样的句柄设备的
	mdc = CreateCompatibleDC(hdc);//空位图设备
	bdc = CreateCompatibleDC(hdc); //背景图设备
								   //设置为高级模式
	SetGraphicsMode(hdc, GM_ADVANCED);
	SetGraphicsMode(mdc, GM_ADVANCED);
	SetGraphicsMode(bdc, GM_ADVANCED);



	bmp = CreateCompatibleBitmap(hdc, mh_w, mh_h);
	SelectObject(mdc, bmp);//空位图到设备
}
void GameBitmap::LoadBmp(const char *BmpName, int w, int h)//重载只有背景图
{
	m_w = w;
	m_h = h;
	backbmp = (HBITMAP)LoadImageA(NULL, BmpName, IMAGE_BITMAP, mh_w, mh_h, LR_LOADFROMFILE);//A为char*
}
void GameBitmap::LoadBmp(const char *BmpName, int w, int h, const char *Heroname, int wH, int hH)//重载有背景和英雄
{
	m_w = wH;
	m_h = hH;
	backbmp = (HBITMAP)LoadImageA(NULL, BmpName, IMAGE_BITMAP, mh_w, mh_h, LR_LOADFROMFILE);//A为char*
	Herobmp = (HBITMAP)LoadImageA(NULL, Heroname, IMAGE_BITMAP, wH, hH, LR_LOADFROMFILE);
}
void GameBitmap::LoadHero_Bmp(const char *Heroname, int w, int h)//加载只有英雄和它的宽高
{
	m_w = w;
	m_h = h;
	Herobmp = (HBITMAP)LoadImageA(NULL, Heroname, IMAGE_BITMAP, w, h, LR_LOADFROMFILE);//我只显示原来的宽高
}
void GameBitmap::LoadArms_Bmp(const char *Armsname, int w, int h)//加载武器位图和它的原来的宽高
{
	mw = w;
	mh = h;
	Armsbmp = (HBITMAP)LoadImageA(NULL, Armsname, IMAGE_BITMAP, w, h, LR_LOADFROMFILE);//我只显示原来的宽高
}
void GameBitmap::Render_Hero_Arms_back_Bmp(int Mainx, int Mainy, int Mousex, int Mousey)//显示英雄与武器与背景，可能需要控制英雄和武器的坐标,都要透明
{
	//谁先谁在底
	SelectObject(bdc, backbmp);//背景
	BitBlt(mdc, 0, 0, mh_w, mh_h, bdc, 0, 0, SRCCOPY);

	SelectObject(bdc, Herobmp);//英雄到mdc
	TransparentBlt(mdc, Mainx, Mainy, m_w, m_h, bdc, 0, 0, m_w, m_h, 0xFFFFFF);

	SelectObject(bdc, Armsbmp);//武器到mdc
	TransparentBlt(mdc, Mousex, Mousey, mw, mh, bdc, 0, 0, mw, mh, 0xFF00FF);

	//float mAngle = 100.0f;
	//Matrix3 m;
	//m.Rotate_d(mAngle).Translate(Mousex, Mousey);
	//m.Identity();
	//SetWorldTransform(mdc, &m);

	BitBlt(hdc, 0, 0, mh_w, mh_h, mdc, 0, 0, SRCCOPY);
}
void GameBitmap::RenderBmp()//有背景图片和英雄
{
	SelectObject(bdc, backbmp);
	BitBlt(mdc, 0, 0, mh_w, mh_h, bdc, 0, 0, SRCCOPY);

	SelectObject(bdc, Herobmp);
	TransparentBlt(mdc, 0, 0, m_w, m_h, bdc, 0, 0, m_w, m_h, 0xFF00FF);

	BitBlt(hdc, 0, 0, mh_w, mh_h, mdc, 0, 0, SRCCOPY);
}
void GameBitmap::RenderbackBmp()//显示只有背景图片
{
	SelectObject(bdc, backbmp);
	BitBlt(mdc, 0, 0, mh_w, mh_h, bdc, 0, 0, SRCCOPY);
	BitBlt(hdc, 0, 0, mh_w, mh_h, mdc, 0, 0, SRCCOPY);
}
void GameBitmap::RenderBmp(int Mainx, int Mainy)//控制英雄移动
{
	SelectObject(bdc, backbmp);
	BitBlt(mdc, 0, 0, mh_w, mh_h, bdc, 0, 0, SRCCOPY);

	SelectObject(bdc, Herobmp);
	TransparentBlt(mdc, Mainx, Mainy, m_w, m_h, bdc, 0, 0, m_w, m_h, 0xFF00FF);

	BitBlt(hdc, 0, 0, mh_w, mh_h, mdc, 0, 0, SRCCOPY);
}
void GameBitmap::Delete(HWND hWnd)
{
	ReleaseDC(hWnd, hdc);

	DeleteObject(mdc);
	DeleteObject(bdc);
	DeleteObject(backbmp);
	DeleteObject(Herobmp);
	DeleteObject(Armsbmp);
	DeleteObject(bmp);
}

//老师的位图方法
//==============================================================
void GameBitmap::Init(HWND hWnd, HINSTANCE hInst)//初始化
{
	mhWnd = hWnd;
	mHinst = hInst;

	mHDC = ::GetDC(hWnd);
	GetClientRect(hWnd, &mRect);
	mWidth = mRect.right - mRect.left;//客户区的宽高
	mHeight = mRect.bottom - mRect.top;
	mMDC = CreateCompatibleDC(mHDC);//mdc与我们的hdc相兼容
									//设置为高级模式
	SetGraphicsMode(mMDC, GM_ADVANCED);

	HBITMAP mBMP;//位图的句柄
	mBMP = CreateCompatibleBitmap(mHDC, mWidth, mHeight);//好像是空位图
	DeleteObject(SelectObject(mMDC, mBMP));
	DeleteObject(mBMP);
}
void GameBitmap::Begin()
{
	//用浅灰色填充掉后备DC的颜色数据
	FillRect(mMDC, &mRect, (HBRUSH)GetStockObject(WHITE_BRUSH));
}
void GameBitmap::End()
{
	//mdc到hdc里
	BitBlt(mHDC, 0, 0, mWidth, mHeight, mMDC, 0, 0, SRCCOPY);
}
int GameBitmap::Load_Bmp(const char *BmpName)
{
	if (BmpName == NULL) { return -1; }
	HBITMAP bmp = (HBITMAP)LoadImageA(mHinst, BmpName, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
	if (bmp == NULL) { return -2; }

	HDC bdc = CreateCompatibleDC(mHDC);
	HBITMAP old = (HBITMAP)SelectObject(bdc, bmp);
	DeleteObject(old);
	DeleteObject(bmp);
	for (int i = 0; i < (int)mBmps.size(); i++)
	{
		if (mBmps[i] == NULL)
		{
			mBmps[i] = bdc;//写到链表里
			return i;
		}
	}
	mBmps.push_back(bdc);
	return (int)(mBmps.size() - 1);
}
int GameBitmap::Load_Bmp(const char *BmpName, int x, int y)
{
	if (BmpName == NULL) { return -1; }
	HBITMAP bmp = (HBITMAP)LoadImageA(mHinst, BmpName, IMAGE_BITMAP, x, y, LR_LOADFROMFILE);
	if (bmp == NULL) { return -2; }

	HDC bdc = CreateCompatibleDC(mHDC);
	HBITMAP old = (HBITMAP)SelectObject(bdc, bmp);
	DeleteObject(old);
	DeleteObject(bmp);
	for (int i = 0; i < (int)mBmps.size(); i++)
	{
		if (mBmps[i] == NULL)
		{
			mBmps[i] = bdc;//写到链表里
			return i;
		}
	}
	mBmps.push_back(bdc);
	return (int)(mBmps.size() - 1);
}
void GameBitmap::DrawBmp1(int bmpid, int sx, int sy, int w, int h, int srcx, int srcy)//绘图风格1
{
	BitBlt(mMDC, sx, sy, w, h, mBmps[bmpid], srcx, srcy, SRCCOPY);//bdc到mdc
}
void GameBitmap::DrawBmp2(int bmpid, int dx, int dy, int dw, int dh, int sx, int sy, int sw, int sh, DWORD color)//绘图风格2
{
	//位图的透明风格
	TransparentBlt(mMDC, dx, dy, dw, dh, mBmps[bmpid], sx, sy, sw, sh, color);//color是要透明的颜色
}
void GameBitmap::ReleaseBmp(int bmpid)
{
	DeleteDC(mBmps[bmpid]);
	mBmps[bmpid] = NULL;
	DeleteDC(mHDC);
	DeleteDC(mMDC);
}
void GameBitmap::SetWorldTransform(XFORM &m)
{
	::SetWorldTransform(mMDC, &m);
}

void GameBitmap::DrawRectangle2(int cx, int cy, int w, int h, DWORD color1, DWORD color2)//边框颜色和填充颜色
{
	HPEN hp = CreatePen(PS_SOLID, 1, color1);
	HPEN op = (HPEN)SelectObject(mMDC, hp);
	HBRUSH hb = CreateSolidBrush(color2);
	HBRUSH ob = (HBRUSH)SelectObject(mMDC, hb);
	Rectangle(mMDC, cx, cy, cx + w, cy + h);
	SelectObject(mMDC, op);
	SelectObject(mMDC, ob);
	DeleteObject(hp);
	DeleteObject(hb);
}
//老师的字符串方法
//==============================================================
int GameBitmap::LoadFont(const char *FontName, int w, int h)//字体加载
{
	LOGFONTA font;

	font.lfHeight = h;
	font.lfWidth = w;
	font.lfEscapement = 0;
	font.lfOrientation = 0;
	font.lfWeight = FW_NORMAL;
	font.lfItalic = 0;
	font.lfUnderline = 0;
	font.lfStrikeOut = 0;
	font.lfCharSet = DEFAULT_CHARSET;
	font.lfOutPrecision = OUT_DEFAULT_PRECIS;
	font.lfClipPrecision = CLIP_DEFAULT_PRECIS;
	font.lfQuality = DEFAULT_QUALITY;
	font.lfPitchAndFamily = DEFAULT_PITCH | FF_DONTCARE;
	strcpy_s(font.lfFaceName, FontName);
	HFONT pf = CreateFontIndirectA(&font);

	for (int i = 0; i < (int)mFonts.size(); i++)
	{
		if (mFonts[i] == NULL)
		{
			mFonts[i] = pf;
			return i;
		}
	}
	mFonts.push_back(pf);
	return (int)(mFonts.size() - 1);
}
void GameBitmap::DrawString_1(int Fontid, int sx, int sy, const char *string, int color)//字符串显示风格1
{
	HFONT oldFont = NULL;
	if (Fontid<0 || Fontid >= (int)mFonts.size()) { return; }
	else {
		if (mFonts[Fontid] != NULL)
		{
			oldFont = (HFONT)SelectObject(mMDC, mFonts[Fontid]);
		}
	}
	SetBkMode(mMDC, TRANSPARENT);//设置文本的背景为透明
	//SetBkColor(mMDC,RGB(255,0,0));//设置文本背景颜色
	SetTextColor(mMDC, color);
	TextOutA(mMDC, sx, sy, string, strlen(string));
	if (oldFont != NULL) { SelectObject(mMDC, oldFont); }
}