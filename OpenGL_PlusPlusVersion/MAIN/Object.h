#pragma once

class Object
{
public:
	int m_Windows_X = 100;
	int m_Windows_Y = 100;
	int m_WindowsWidth = 800;
	int m_WindowsHeight = 600;

	//摄像机看向的位置
	float m_LookAt_X = 0;
	float m_LookAt_Y = 0;
	float m_LookAt_Z = 0;

	//摄像机的位置
	float m_CameraPos_X = 0;
	float m_CameraPos_Y = 50;
	float m_CameraPos_Z = 200;

	float m_MoveSpeed_X = 10.0f;
	float m_MoveSpeed_Y = 10.0f;
	float m_MoveSpeed_Z = 10.0f;


	virtual void Start();
	virtual void Update();
	virtual void End();

	//普通键盘按键回调
	virtual void OnOrdinaryKeyboardDownEvent(unsigned char Key, int X, int Y);
	virtual void OnOrdinaryKeyboardUpEvent(unsigned char Key, int X, int Y);
	//功能键盘按键回调
	virtual void OnSpecialKeyboardDownEvent(int Key, int X, int Y);
	virtual void OnSpecialKeyboardUpEvent(int Key, int X, int Y);
	//鼠标回调
	//鼠标完整的点击事件
	//:::::::::::::::::::::::::::::::::::::::::::::::::::左中右前滚轮后滚轮 0,1,2,3,4   :::::::::::::::::::::按下抬起 0,1
	virtual void OnMouseClickEvent(int Button, int State, int Mouse_X, int Mouse_Y);
	//鼠标滑动
	virtual void OnMouseMoveEvent(int Mouse_X, int Mouse_Y);
	//鼠标拖拽
	virtual void OnMousePassiveEvent(int Mouse_X, int Mouse_Y);
};
