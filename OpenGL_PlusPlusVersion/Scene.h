#pragma once
#define MAINATENGINE "MAIN/OpenGL_AY_Engine.h"
#include MAINATENGINE


///*

///普通键盘按键回调
/// void OnOrdinaryKeyboardDownEvent(unsigned char Key, int X, int Y);
///std::cout << "普通按下！" << Key << " X = " << X << " Y = " << Y << std::endl;
/// void OnOrdinaryKeyboardUpEvent(unsigned char Key, int X, int Y);
///std::cout << "普通抬起！" << Key << " X = " << X << " Y = " << Y << std::endl;
///功能键盘按键回调
/// void OnSpecialKeyboardDownEvent(int Key, int X, int Y);
///std::cout << "功能按下！" << Key << " X = " << X << " Y = " << Y << std::endl;
/// void OnSpecialKeyboardUpEvent(int Key, int X, int Y);
///std::cout << "功能抬起！" <<Key<<" X = "<<X<<" Y = "<<Y<< std::endl;
///鼠标回调
///鼠标完整的点击事件
///:::::::::::::::::::::::::::::::::::::::::::::::::::左中右前滚轮后滚轮 0,1,2,3,4   :::::::::::::::::::::按下抬起 0,1
/// void OnMouseClickEvent(int Button, int State, int Mouse_X, int Mouse_Y);
///std::cout << "Button =" << Button << " State = " << State << " X = " << X << " Y = " << Y << std::endl;
///鼠标滑动
/// void OnMouseMoveEvent(int Mouse_X, int Mouse_Y);
///std::cout << "鼠标移动 " << "X = " << Mouse_X << " Y = " << Mouse_Y << std::endl;
///鼠标拖拽
/// void OnMousePassiveEvent(int Mouse_X, int Mouse_Y);
///std::cout << "鼠标拖拽 " << "X = " << Mouse_X << " Y = " << Mouse_Y << std::endl;


///float Angle = 0;
///float p = 0;
///Sprite *S = NULL;
///S = new Sprite();
///S->Create("1.bmp");

///S->SetSpriteScale(-2.0, 1);
///S->DrawSprite();
///===============================================================================
///ATENGINE->ATENGINE_MatrixMode();
///ATENGINE->Rotate(++Angle, 0, 0, 1);
///ATENGINE->CreateTriangle(ATATRGB::RED, ATATPOS2D(-100, 0),
	///ATATRGB::GREEN, ATATPOS2D(100, 0), ATATRGB::WHITE, ATATPOS2D(0, 100));
///ATENGINE->DrawEnd();

///*///



class Scene:public Object
{
	float Angle = 0;
	float p = 0;

	Sprite *S = NULL;
public:
	virtual void Start();
	virtual void Update();
	virtual void End();

	virtual void OnOrdinaryKeyboardDownEvent(unsigned char Key, int X, int Y);
	virtual void OnMouseMoveEvent(int Mouse_X, int Mouse_Y);
};