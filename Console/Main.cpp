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

class PASS
{
	char m_Password[256] = { 0 };
	bool m_True = false;
	bool m_Exit = false;
	int m_Number = 0;
	bool m_PassOk = false;
	const char m_Account[30][256] = {
		"( Account:  c18c15f6e5cbffa1740ac956331c2c23" ,//1979304986
		"( Account: bc1350b3f195f4ccc830130ea6196f32",//2540326113
		"( Account: 27e6521069f26c5e087ed6bb97c79119",//2013534308
		"( Account: 2875af0624e386c3f461f073b9d3d10c",//1405898636
		"( Account: 17150657dfc85a6359aa206d90fd9427",//1428231203
		"( Account: 3e3643a9f0d2d5a7eb038eeca9edea23",//3519165647
		"( Account: 2c993a7c5b0439245dfd9b1b1f297c39",//2996525939
		"( Account: 7d1055319072572c2958125cb8a89b56",//15982683979
		"( Account:7d1055319072572c2958125cb8a89b56@163.com ",//
		"( Account:7d1055319072572c2958125cb8a89b56@163.com ",//
		"( Account:zhm520bn@gmail.com ",//
		"( Account: 1493065d281ef387b7aecf0e48d71d46",//YFKZHM
		"( Account:zhm520bn@yahoo.com ",//
		"(其 " };

	const char m_Password_[30][256] = {
		" Password:zhm.@.723d505516e0c197e42a6be3c0af910e.@ )",
		" Password:zhm.@.723d505516e0c197e42a6be3c0af910e.X )",
		" Password:1155.665.zhm )",
		" Password:zhanghaoman.1314 )",
		" Password:1155.665.@. )",
		" Password:zhm.@.723d505516e0c197e42a6be3c0af910e.W )",
		" Password:zhm.@.723d505516e0c197e42a6be3c0af910e )",
		" Password:zhm.@.723d505516e0c197e42a6be3c0af910e.c )",
		" Password:zhm.@.723d505516e0c197e42a6be3c0af910e.y )",
		" Password:zhm.@.723d505516e0c197e42a6be3c0af910e.C )",
		" Password:zhm.@.723d505516e0c197e42a6be3c0af910e.c )",
		" Password:YFK520UIZHMzhm )",
		" Password:zhm.@.723d505516e0c197e42a6be3c0af910e.c )",
		" 他 )" };
public:
	bool EnterPassword()
	{
		std::cout << "输入Password：";
		std::cin >> m_Password;

		int len = 0;
		len = strlen(_password);
		for (int i = 0; i <= len; i++)
		{
			if (m_Password[i] != _password[i])
			{
				m_True = false;
				return false;
				break;
			}
		}
		m_True = true;
		return true;
	}
	bool Run()
	{
		while (true)
		{
			if (!m_Exit)
			{
				if (m_True)
				{
					if (m_PassOk == false)
					{
						std::cout << "密码正确" << std::endl;
						Sleep(500);
					}
					system("cls");
					_PasswordList();
				}
				else
				{
					std::cout << "密码不正确，重新输入！" << std::endl;
					Sleep(500);
					system("cls");
					EnterPassword();
				}
			}
		}
		return true;
	}
private:
	void _InsetInfo_End(const char *Buf, FILE *File)
	{
		fwrite(Buf, strlen(Buf), 1, File);
		fclose(File);
		File = NULL;
	}
	FILE *_InsetFile_Begin(const char *Account, const char *Password)
	{
		FILE *File = NULL;
		fopen_s(&File, "Text.txt", "w+");
		if (File)
		{
			fwrite(Account, strlen(Account), 1, File);
			fwrite(Password, strlen(Password), 1, File);
			fwrite("\r\n", sizeof("\r\n"), 1, File);
		}
		return File;
	}
	int _PasswordList()
	{
		m_PassOk = true;
		std::cout << " 1979304986 密码信息 获取信息按1将按文件输出" << std::endl;
		std::cout << " 2540326113 密码信息 获取信息按2将按文件输出" << std::endl;
		std::cout << " 2013534308 密码信息 获取信息按3将按文件输出" << std::endl;
		std::cout << " 1405898636 密码信息 获取信息按4将按文件输出" << std::endl;
		std::cout << " 1428231203 密码信息 获取信息按5将按文件输出" << std::endl;
		std::cout << " 3519165647 密码信息 获取信息按6将按文件输出(账号不建议使用)" << std::endl;
		std::cout << " 2996525939 密码信息 获取信息按7将按文件输出" << std::endl;
		std::cout << " 微软账号   密码信息 获取信息按8将按文件输出" << std::endl;
		std::cout << " 163邮件    密码信息 获取信息按9将按文件输出" << std::endl;
		std::cout << " Adobe      密码信息 获取信息按10将按文件输出" << std::endl;
		std::cout << " Google Email 密码信息 获取信息按11将按文件输出" << std::endl;
		std::cout << "终结支付密码,Bank密码信息按5000不按文件输出，将直接显示" << std::endl;
		std::cout << "丝绸之路 3.1 密码信息 获取信息按12将按文件输出" << std::endl;
		std::cout << "Yahoo Email 密码信息 获取信息按13将按文件输出" << std::endl;
		std::cout << "其他可有的14" << std::endl;
		std::cout << "                                          " << std::endl;
		std::cout << " 5176 / 0(退出)，请输入信息按键编号：";
		std::cin >> m_Number;

		switch (m_Number)
		{
		case 1: {_1979304986(m_Account[0], m_Password_[0]); }; break;
		case 2: {_2540326113(m_Account[1], m_Password_[1]); }; break;
		case 3: {_2013534308(m_Account[2], m_Password_[2]); }; break;
		case 4: {_1405898636(m_Account[3], m_Password_[3]); }; break;
		case 5: {_1428231203(m_Account[4], m_Password_[4]); }; break;
		case 6: {_3519165647(m_Account[5], m_Password_[5]); }; break;
		case 7: {_2996525939(m_Account[6], m_Password_[6]); }; break;
		case 8: {_MicrosoftAccount(m_Account[7], m_Password_[7]); }; break;
		case 9: {_163EmailAccount(m_Account[8], m_Password_[8]); }; break;
		case 10: {_AdobeAccount(m_Account[9], m_Password_[9]); }; break;
		case 11: {_GoogleAccount(m_Account[10], m_Password_[10]); }; break;
		case 12: {_Silk_Road(m_Account[11], m_Password_[11]); }; break;
		case 13: {_YahooAccount(m_Account[12], m_Password_[12]); }; break;
		case 14: {_Any(m_Account[13], m_Password_[13]); }; break;
		case 0: {exit(0); }; break;
		case 5000: {__Password__(); }; break;
		case 5176: {exit(0); }; break;
		}
		return -1;
	}
	//以下都是兄弟号
	void _1979304986(const char *Account, const char *Password)
	{
		FILE *File = _InsetFile_Begin(Account, Password);
		const char *Buf = "2010年申请,5e30d7a2f1825abb3ef4a72d78430ebe为当时第一个密码,当前邮件和财付通二次,微云独立密码为：aad3b6efbea6ac3d2fa97e14098f8eed.@.723d505516e0c197e42a6be3c0af910e.M\r\n \
身份证号：我的,财付通的支付为1f51e4ba2df7f5f3b239126a0398f03d.。用过的密码:5e30d7a2f1825abb3ef4a72d78430ebe zhm.@.5201314.c zhm.@.5201314.m \r\n \
以前的财付通二次密码验证为:cpy.zhanghaoman 或者是 zhanghaoman.cpy\r\n \
当前绑定的手机号码为：7d1055319072572c2958125cb8a89b56 有些信息头填真实的";
		_InsetInfo_End(Buf, File);
		ExportFunction();
	}
	void _2540326113(const char *Account, const char *Password)
	{
		FILE *File = _InsetFile_Begin(Account, Password);
		const char *Buf = "2012年申请，用过的密码：cpy.zhanghaoman zhm.@.5201314.x zhm.@.5201314.X 已绑定手机\r\n \
我的身份证信息申诉，未设置其他功能，绑定的手机号：7d1055319072572c2958125cb8a89b56";
		_InsetInfo_End(Buf, File);
		ExportFunction();
	}
	void _2013534308(const char *Account, const char *Password)
	{
		FILE *File = _InsetFile_Begin(Account, Password);
		const char *Buf = "2014年申请，用过的密码：1155.665.zhm 申请时的密码,现在一直未更改哦 已绑定手机\r\n \
我的身份证信息申诉，未设置其他功能，绑定的手机号：7d1055319072572c2958125cb8a89b56";
		_InsetInfo_End(Buf, File);
		ExportFunction();
	}
	void _1405898636(const char *Account, const char *Password)
	{
		FILE *File = _InsetFile_Begin(Account, Password);
		const char *Buf = "2014年申请，用过的密码：zhanghaoman.1314  申请时的密码,现在一直未更改哦 未绑定手机\r\n \
我的身份证信息申诉，未设置其他功能";
		_InsetInfo_End(Buf, File);
		ExportFunction();
	}
	void _1428231203(const char *Account, const char *Password)
	{
		FILE *File = _InsetFile_Begin(Account, Password);
		const char *Buf = "2014年申请，用过的密码：1155.665.cha 申请时的密码 已绑定手机\r\n \
我的身份证信息申诉，未设置其他功能，绑定的手机号：7d1055319072572c2958125cb8a89b56";
		_InsetInfo_End(Buf, File);
		ExportFunction();
	}
	void _3519165647(const char *Account, const char *Password)
	{
		FILE *File = _InsetFile_Begin(Account, Password);
		const char *Buf = "2017年申请，用过的密码：zhm.@.5201314.W ,已绑定手机\r\n \
我的身份证信息申诉，未设置其他功能，绑定的手机号：7d1055319072572c2958125cb8a89b56";
		_InsetInfo_End(Buf, File);
		ExportFunction();
	}
	void _2996525939(const char *Account, const char *Password)
	{
		FILE *File = _InsetFile_Begin(Account, Password);
		const char *Buf = "2015年申请，用过的密码：zhm.@.5201314 ,现在一直未更改哦 已绑定手机\r\n \
我的身份证信息申诉，未设置其他功能，绑定的手机号：7d1055319072572c2958125cb8a89b56";
		_InsetInfo_End(Buf, File);
		ExportFunction();
	}
	void _MicrosoftAccount(const char *Account, const char *Password)
	{
		FILE *File = _InsetFile_Begin(Account, Password);
		const char *Buf = "2018申请 绑定的手机号：15982683979 绑定的邮件：15982683979@163.com";
		_InsetInfo_End(Buf, File);
		ExportFunction();
	}
	void _163EmailAccount(const char *Account, const char *Password)
	{
		FILE *File = _InsetFile_Begin(Account, Password);
		const char *Buf = "2014申请 绑定的手机号：15982683979 如果有手机授权密码：则为zhm520";
		_InsetInfo_End(Buf, File);
		ExportFunction();
	}
	void _AdobeAccount(const char *Account, const char *Password)
	{
		FILE *File = _InsetFile_Begin(Account, Password);
		const char *Buf = "2018申请 绑定的手机号：15982683979";
		_InsetInfo_End(Buf, File);
		ExportFunction();
	}
	void _GoogleAccount(const char *Account, const char *Password)
	{
		FILE *File = _InsetFile_Begin(Account, Password);
		const char *Buf = "2016申请 绑定的手机号：15982683979";
		_InsetInfo_End(Buf, File);
		ExportFunction();
	}
	void __Password__()
	{
		std::cout << "    926498    " << std::endl;
		std::cout << "输出成功！" << std::endl;
		Sleep(2000);
		m_Number = 0;
	}
	void _Silk_Road(const char *Account, const char *Password)
	{
		FILE *File = _InsetFile_Begin(Account, Password);
		const char *Buf = "2019.217 申请 恢复pin:926498 \r\n \
一些网址：https://xtg6zekabihp7sol.onion/ \r\n \
http://k4btcoezc5tlxyaf.onion/";
		_InsetInfo_End(Buf, File);
		ExportFunction();
	}
	void _YahooAccount(const char *Account, const char *Password)
	{
		FILE *File = _InsetFile_Begin(Account, Password);
		const char *Buf = "2017申请 绑定的手机号：15982683979";
		_InsetInfo_End(Buf, File);
		ExportFunction();
	}
	void _Any(const char *Account, const char *Password)
	{
		FILE *File = _InsetFile_Begin(Account, Password);
		const char *Buf = "OCT 3Dmax 视频剪辑HitFilm 谷歌 贝贝 雅虎 NordVPN Bestgor 微信和大号的密码一样,同步的  密码都是：zhm.@.723d505516e0c197e42a6be3c0af910e.c \r\n \
         比特币的第二次密码也是 pin一样 招商也是 京东也是 CSDN是大写的C 蜡笔也是 交通:cpy.zhm zhm.1f51e4ba2df7f5f3b239126a0398f03d 163邮件的授权\r\n \
         为zhm520 \r\n \
         Unity:15982683979@163.com/zhm520 zhm.@.723d505516e0c197e42a6be3c0af910e.Unity\r\n \
         cocos:zhmmmm zhm520\r\n \
         GITTHUB zhmmmm zhm.@.723d505516e0c197e42a6be3c0af910e.c\r\n \
         四川汽车客运:15982683979/15982683979@163.com  1f51e4ba2df7f5f3b239126a0398f03d\r\n \
         Codewarrior软件: 15982683979@163.com zhm.@.723d505516e0c197e42a6be3c0af910e.c\r\n \
         百度云:15982683979 17856af0ef8cd344480bc9c1d6683622\r\n \
         支付宝:15982683979 15982683979.1\r\n \
         优酷:15982683979@163.com zhm.@.723d505516e0c197e42a6be3c0af910e.Y \r\n \
         银行卡的密码为那几位数字\r\n \
         6688卡盟:zhmmmm zhm520\r\n \
         6m5m素材网:zhmmmm zhm520 \r\n \r\n \
         name,url,username,password\r\n \r\n \
         dl.reg.163.com, https://dl.reg.163.com/webzj/m163_1.0.1/pub/index_dl.html, \r\n \
		15982683979,zhanghaoman.1314 \r\n \
         webzj.reg.163.com, https ://webzj.reg.163.com/v1.0.1/pub/index_dl.html,\r\n \
		15982683979,zhm.@.5201314. \r\n \
         gps.66ve.com, http ://gps.66ve.com/reg.asp,\r\n \
		zhmmmm,zhm.@.520 \r\n \
         www.6m5m.com, http ://www.6m5m.com/register.html,\r\n \
			 zhmmmm,zhm520 \r\n \
         adobeid - na1.services.adobe.com, https ://adobeid-na1.services.adobe.com/renga-idprovider/pages/login.do,\r\n \
			 15982683979@163.com,zhm.@.5201314.C \r\n \
         www.bestgore.com, http ://www.bestgore.com/wp-login.php,\r\n \
			 zhm520bnmmm,zhm.@.5201314. \r\n \
         www.bestgore.com, https ://www.bestgore.com/wp-login.php,\r\n \
			 zhm520bnmmm,zhm.@.5201314. \r\n \
         blockchain.info, https ://blockchain.info/wallet/,\r\n \
			 41c1b0e8-0deb-4c71-b5d6-997b7a29cf35,yangyu.5201314 \r\n \
         www.break.com, http ://www.break.com/user/register,\r\n \
			 zhm520bn@gmail.com,zhm.@.5201314.c \r\n \
         cocos2d - x.org, https ://cocos2d-x.org/u/login,\r\n \
			 15982683979@163.com,zhm520 \r\n \
         www.facebook.com, https ://www.facebook.com/login/,\r\n \
			 15982683979,zhm.@.5201314.c \r\n \
         fxhome.com, https ://fxhome.com/getting-started,\r\n \
			 yanpingZha,zhm.@.5201314.c \r\n \
         fxhome.com, https ://fxhome.com/express,\r\n \
			 zhm520bn@gmail.com,zhm.@.5201314.c \r\n \
         github.com, https ://github.com/login,\r\n \
			 zhm520bn@gmail.com,zhm.@.5201314.c \r\n \
         www.incredibuild.com, https ://www.incredibuild.com/FreeVisualStudioLicense,\r\n \
			 zhmmmm,zhmmmm520 \r\n \
         www.instagram.com, https ://www.instagram.com/accounts/signup,\r\n \
			 chayanping,zhm.@.5201314.c \r\n \
         signup.jp.leagueoflegends.com, https ://signup.jp.leagueoflegends.com/ja/signup/index,\r\n \
			 zhmmmm,zhm520 \r\n \
         login.live.com, https ://login.live.com/oauth20_authorize.srf,\r\n \
			 15982683979@163.com,zhm.@.5201314.c \r\n \
         localbitcoins.com, https ://localbitcoins.com/accounts/login/,\r\n \
			 zhm520bn@gmail.com,zhm.mmmmm 41c1b0e8-0deb-4c71-b5d6-997b7a29cf35 \r\n \
           \
         41c1b0e8 - 0deb - 4c71 - b5d6 - 997b7a29cf35 \r\n \
         qzhlk9jfq0um44dfqa3t249swm2talepxqsxm8tsrx \r\n \
         yangyu.5201314 \r\n \
         zhm.@.5201314.c 二次登陆一次性密码 \r\n \
           \
         www.miscopy.com, http://www.miscopy.com/wp-login.php,\r\n \
			 zhm520bnmmm,zhm.@.5201314. \r\n \
         myspace.com, https ://myspace.com/zhm520bnmmm,\r\n \
			 zhm520bn@gmail.com,zhm.@.5201314.c \r\n \
         neowallet.cn, https ://neowallet.cn/,,\r\n \
			 zhm.@.5201314.c \r\n \
         ucp.nordvpn.com, https ://ucp.nordvpn.com/login/,\r\n \
			 zhm520bn@gmail.com,zhm.@.5201314.c \r\n \
         www.nxp.com, https ://www.nxp.com/,\r\n \
			 15982683979@163.com,zhm.@.5201314.c \r\n \
         otcbtc.com, https ://otcbtc.com/,\r\n \
			 15982683979@163.com,zhm.@.5201314.c \r\n \
         api.paymentwall.com, https ://api.paymentwall.com/pwaccount/signup,\r\n \
			 zhm520bn@gmail.com,zhm.@.5201314.c \r\n \
         www.paypal.com, https ://www.paypal.com/signin,\r\n \
			 zhm520bn@gmail.com,zhm.@.5201314.c \r\n \
         www.pornhub.com, https ://www.pornhub.com/signup,\r\n \
			 zhmmmm,zhm520 \r\n \
         auth.quakenet.org, https ://auth.quakenet.org/create_account,\r\n \
			 ANGyu12,zhm520 \r\n \
         auth.quakenet.org, https ://auth.quakenet.org/create_account,\r\n \
			 ZHMmmm,[zhm520] \r\n \
         auth.riotgames.com, https ://auth.riotgames.com/authorize,\r\n \
			 zhmmmm,zhm520 \r\n \
         www.shiyanlou.com, https ://www.shiyanlou.com/courses/605,\r\n \
			 15982683979@163.com,zhm.@.5201314.c \r\n \
         twitter.com, https ://twitter.com/signup,\r\n \
			 +8615982683979,zhm.@.5201314.c \r\n \
         id.unity.com, https ://id.unity.com/ja/conversations/7d6cc20e-c90b-4388-9ba5-1c7f3135854d00df,\r\n \
			 15982683979@163.com,zhm.@.5201314.Unity \r\n \
         login.yahoo.com, https ://login.yahoo.com/account/challenge/password,\r\n \
			 zhm520bn,zhm.@.5201314.c \r\n \
         login.yahoo.com, https ://login.yahoo.com/account/challenge/password,\r\n \
			 zhm520bn@yahoo.com,zhm.@.5201314.c \r\n ";
		_InsetInfo_End(Buf, File);
		ExportFunction();
	}


	void ExportFunction()
	{
		std::cout << "输出成功！" << std::endl;
		Sleep(500);
		m_Number = 0;
	}
	const char *_password = "themyqq321";
};

int Main()
{
	//PASS Obj;
	//Obj.EnterPassword();
	//Obj.Run();


	PASSENGINE Obj;
	Obj.Run();

	//2010年申请, 5e30d7a2f1825abb3ef4a72d78430ebe为当时第一个密码, 当前邮件和财付通二次, 微云独立密码为：aad3b6efbea6ac3d2fa97e14098f8eed.@.723d505516e0c197e42a6be3c0af910e.M\n身份证号：我的, 财付通的支付为1f51e4ba2df7f5f3b239126a0398f03d.。用过的密码:5e30d7a2f1825abb3ef4a72d78430ebe zhm.@.5201314.c zhm.@.5201314.m

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

