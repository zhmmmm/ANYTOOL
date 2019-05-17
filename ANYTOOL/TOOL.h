#pragma once
//引入C#库
#include "stdafx.h"
#using "Tool\\CSharPDDOS_DLL\\CSharPDdos.dll"

//声明代码托管(可要可不要)
#pragma managed

//引用ClassLibrary1命名空间
using namespace CSharPDdos;




//===========================================================
//攻击的IP,端口,线程数
int Init_CSharP_DLL_To_CPlusPlus_DLL(const char *IP, const int Port, int ThreadNumber);
//停止攻击
int Stop_CSharP_DLL_To_CPlusPlus_DLL_DDosAttack();