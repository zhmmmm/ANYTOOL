#pragma once
#include "OpenGL_AY_Engine.h"



class Camera
{
	//摄像机看向的位置
	float m_LookAt_X = 0;
	float m_LookAt_Y = 0;
	float m_LookAt_Z = 0;

	//摄像机的位置
	float m_CameraPos_X = 0;
	float m_CameraPos_Y = 50;
	float m_CameraPos_Z = 200;
public:
	Camera(){}
	Camera(Object Obj);
	Camera(Object *Obj);

	static void CameraToWorld(Object Obj);
	static void CameraToWorld(Object *Obj);
};
