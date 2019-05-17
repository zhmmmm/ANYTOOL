#include "Camera.h"


Camera::Camera(Object Obj)
{
	ATENGINE->ATENGINE_MatrixMode();
	gluLookAt(
		Obj.m_CameraPos_X, Obj.m_CameraPos_Y, Obj.m_CameraPos_Z,//眼睛 (摄像机位置)
		Obj.m_LookAt_X, Obj.m_LookAt_Y, Obj.m_CameraPos_Z - 200,//演员 (摄像机看向的位置)
		0, 1, 0);//摄像机上方的轴向 (表示分出摄像机本身的上下面)
}

Camera::Camera(Object *Obj)
{
	ATENGINE->ATENGINE_MatrixMode();
	gluLookAt(
		Obj->m_CameraPos_X, Obj->m_CameraPos_Y, Obj->m_CameraPos_Z,//眼睛 (摄像机位置)
		Obj->m_LookAt_X, Obj->m_LookAt_Y, Obj->m_CameraPos_Z - 200,//演员 (摄像机看向的位置)
		0, 1, 0);//摄像机上方的轴向 (表示分出摄像机本身的上下面)
}

void Camera::CameraToWorld(Object Obj)
{
	Camera::Camera(Obj);
}
void Camera::CameraToWorld(Object *Obj)
{
	Camera::Camera(*Obj);
}