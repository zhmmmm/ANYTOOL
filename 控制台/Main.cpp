#include <iostream>
#include <map>
#include <Vector>
#include <winsock.h>
#pragma comment(lib,"wsock32.lib")
#include <Windows.h>
#include "PASSWORD.h"

#define Main main

//GetCurrentProcess();//获取当前进程的句柄
//
//CreateRemoteThread(/*指定某个进程的句柄*/, );//创建远程进程,给其他进程注入
//CreateThread();//创建远程进程
//
//OpenProcess();//通过进程ID获取该进程的句柄
//
//LoadLibrary();
//
//WriteProcessMemory(/*指定进程的句柄，
//				   指定写入内存的起始地址
//				   ,指定要写入的内容的缓冲区,
//				   指定写入内容的长度,
//				   接受实际写入内容的长度*/);//写入目标进程中
//
//VirtualAllocEx(/*
//			   指定要申请内存的进程句柄,
//			   指定申请的起始位置,
//			   指定申请长度,
//			   指定申请内存的状态类型,
//			   指定申请内存的内存属性
//			   */);//在目标进程申请内存,返回申请到的内存块的起始地址
//BeginUpdateResourceA();
//UpdateResourceA();
//EndUpdateResourceA();


class Sort
{
public:
	void M(int *Arr, int Len)
	{
		for (int i = 0; i < Len; i++)
		{
			for (int j = i + 1; j < Len; j++)
			{
				if (Arr[i] > Arr[j])
				{
					Arr[i] = Arr[i] ^ Arr[j];
					Arr[j] = Arr[i] ^ Arr[j];
					Arr[i] = Arr[i] ^ Arr[j];
				}
			}
		}
	}
	void X(int *Arr, int Len)
	{
		int Temp = 0;
		for (int i = 0; i < Len - 1; i++)
		{
			Temp = i;
			for (int j = i + 1; j < Len; j++)
			{
				if (Arr[Temp] > Arr[j])
				{
					Temp = j;
				}
			}

			int temp = Arr[i];
			Arr[i] = Arr[Temp];
			Arr[Temp] = temp;
		}
	}
	void C(int *Arr, int Len)
	{
		int TempData = 0;
		int i = 0;
		int j = 0;
		for (i = 1; i < Len; i++)
		{
			j = i;
			TempData = *(Arr + i);
			while (j > 0 && TempData < Arr[j - 1])
			{
				Arr[j] = Arr[j - 1];
				j--;
			}
			Arr[j] = TempData;
		}
	}
	void T(int *Arr, int Len)
	{
		for (int n = 1; n <= 100; n *= 10)
		{
			int Temp[10][100] = { 0 };
			for (int i = 0; i < Len; i++)
			{
				int m = (Arr[i] / n) % 10;
				Temp[m][i] = Arr[i];
			}
			int k = 0;
			for (int i = 0; i < 10; i++)
			{
				for (int j = 0; j < Len; j++)
				{
					if (Temp[i][j] != 0)
					{
						Arr[k] = Temp[i][j];
						k++;
					}
				}
			}
		}
	}
	void K(int *Arr, int low, int high)
	{
		if (low >= high)
		{
			return;
		}
		int first = low;
		int last = high;
		int key = Arr[first];/*用字表的第一个记录作为枢轴*/

		while (first < last)
		{
			while (first < last && Arr[last] >= key)
			{
				--last;
			}

			Arr[first] = Arr[last];/*将比第一个小的移到低端*/

			while (first < last && Arr[first] <= key)
			{
				++first;
			}

			Arr[last] = Arr[first];
			/*将比第一个大的移到高端*/
		}
		Arr[first] = key;/*枢轴记录到位*/
		K(Arr, low, first - 1);
		K(Arr, first + 1, high);
	}
	void Z(int *Arr, int Len)
	{
		for (int i = 1; i < Len; i++)
		{
			int tmp = Arr[i];
			int low = 0;
			int high = i - 1;

			// 不断折半，寻找合适的插入位置  
			while (low <= high)
			{
				int mid = (low + high) / 2;

				if (tmp > Arr[mid])
				{
					low = mid + 1;
				}
				else
				{
					high = mid - 1;
				}
			}
			// 依次将元素后移  
			for (int j = i; j > low; j--)
			{
				Arr[j] = Arr[j - 1];
			}
			Arr[low] = tmp;
		}
	}
};

BOOL BASS_Init(const char *ProjectPath_Debug)
{
	char Str[256] = "copy C:\\Windows\\SysWOW64\\bass.dll ";
	strcat_s(Str, 256, ProjectPath_Debug);
	int State = system(Str);
	return TRUE;
}
void ComputerName_Ip(char *ch0, char *ch1)
{
	char buf[256] = "";
	hostent *ph = NULL;//struct hostent *ph = NULL;
	WSADATA w;
	WSAStartup(0x0101, &w);//这一行必须在使用任何SOCKET函数前写！


	gethostname(buf, 256);
	memcpy_s(ch0, 256, buf, 256);
	std::string hostName = buf;//此处获得本机名称

	ph = gethostbyname(buf);
	const char *IP = inet_ntoa(*((struct in_addr *)ph->h_addr_list[0]));//此处获得本机IP
	memcpy_s(ch1, 256, IP, 256);

	std::cout << "计算机名：" << hostName.c_str() << std::endl;
	std::cout << "计算机IP：" << IP << std::endl;

	WSACleanup();
}



int Main()
{
	//PASS Obj;
	//Obj.EnterPassword();
	//Obj.Run();


	PASSENGINE Obj;
	Obj.Run();

	

	//一个好玩的程序

	//wchar_t SelfName[] = L"C:\\Users\\Administrator\\Desktop\\Experiment\\Debug\\Experiment.exe";
	//wchar_t TargetName[] = L"C:\\Users\\Administrator\\Desktop\\Experiment\\Experiment\\exe.c";



	//CopyFile(SelfName,TargetName,FALSE);

	system("pause");
	return 0;
}
//GetModuleFileName(NULL,Buf,BufSize);获取当前运行程序路径
//CopyFile(SelfName,TargetName,FALSE);拷贝文件,从哪里拷,拷到哪里后的新Name.源后缀,并覆盖
//GetSystemDirectory(Buf,BufSize);获取系统目录

