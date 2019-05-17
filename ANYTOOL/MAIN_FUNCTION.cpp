#include "stdafx.h"
#include "MAIN_FUNCTION.h"

void FUNCTION::INIT_CEditControl(CEdit *CEditControl, CString Text)
{
	CEditControl->SetWindowTextW(Text);
}
void FUNCTION::Set_CEditControl(CEdit *CEditControl, CString Text)
{
	CEditControl->SetWindowTextW(Text);

}

const char * FUNCTION::CString_To_ConstChar(CString String)
{
	if (String)
	{
		//三种方法
		//USES_CONVERSION;
		//std::string str(W2A(String));

		//CStringA temp;
		//temp = Port;
		//char *p = temp.GetBuffer();

		m_String.clear();
		m_String = CT2A(String);

		return m_String.c_str();
	}
	return nullptr;
}

string FUNCTION::CString_To_String(CString String)
{
	USES_CONVERSION;
	std::string ToString(W2A(String));
	return ToString;
}

char *FUNCTION::GetCur_ExeRunPath(char *Buffer, int BufferLen)
{
	wchar_t Buf[256] = { 0 };
	GetModuleFileName(NULL, Buf, sizeof(Buf));
	char BufTemp[256] = { 0 };
	for (int i = 0; i < 256; i++)
	{
		if (Buf[i])
		{
			BufTemp[i] = (char)Buf[i];
		}
		else
		{
			break;
		}

	}
	std::cout << "exe 运行目录 " << BufTemp << std::endl;
	int BufLen = strlen(BufTemp);
	const char *AnyTool = "ANYTOOL";
	char Path[256] = { 0 };
	for (int i = 0; i < BufLen; i++)
	{
		bool Jump = true;
		if (BufTemp[i] == 'A')
		{
			for (int j = 0; j < 7; j++)
			{
				//如果有一个不等则跳出去继续赋值
				if (BufTemp[i + j] != AnyTool[j])
				{
					Jump = true;
					break;
				}
				else
				{
					Jump = false;
				}
			}
		}
		if (Jump)
		{
			Path[i] = BufTemp[i];
		}
		else
		{
			for (int j = 0; j < 7; j++)
			{
				Path[i + j] = AnyTool[j];
			}
			break;
		}
	}
	for (int i = 0; i < BufferLen; i++)
	{
		Buffer[i] = Path[i];
	}
	return NULL;
}

int FUNCTION::StartLOIC()
{
	char Path[256] = { 0 };
	MAIN::GetCur_ExeRunPath(Path, sizeof(Path));
	const char *LOIC = "\\ANYTOOL\\Tool\\LOIC.exe";//工具位置,不可更改
	std::cout << "字符串未连接前 " << Path << std::endl;
	strcat_s(Path, LOIC);
	std::cout << "字符串连接后 " << Path << std::endl;
	char PATH[256] = "START ";
	strcat_s(PATH, Path);
	std::cout << PATH << std::endl;
	//只要exe是放在ANYTOOL文件下,工具位置不做更改,都能准确运行需要的功能
	if (system(PATH) == 0)
	{
		std::cout << "低轨道粒子炮启动成功！" << std::endl;
		return 0;
	}
	return -1;
}

int FUNCTION::StartGoldWave()
{
	char Path[256] = { 0 };
	MAIN::GetCur_ExeRunPath(Path, sizeof(Path));
	const char *GoldWave = "\\ANYTOOL\\Tool\\AudioEdit\\GoldWave\\GoldWave.exe";//工具位置,不可更改
	std::cout << "字符串未连接前 " << Path << std::endl;
	strcat_s(Path, GoldWave);
	std::cout << "字符串连接后 " << Path << std::endl;
	char PATH[256] = "START ";
	strcat_s(PATH, Path);
	std::cout << PATH << std::endl;
	//只要exe是放在ANYTOOL文件下,工具位置不做更改,都能准确运行需要的功能
	if (system(PATH) == 0)
	{
		std::cout << "音频剪辑程序启动成功！" << std::endl;
		return 0;
	}
	return -1;
}

int FUNCTION::StartLOICPLUS()
{
	char Path[256] = { 0 };
	MAIN::GetCur_ExeRunPath(Path, sizeof(Path));
	const char *LOIC = "\\ANYTOOL\\Tool\\LOICPLUS\\LOIC.exe";//工具位置,不可更改
	std::cout << "字符串未连接前 " << Path << std::endl;
	strcat_s(Path, LOIC);
	std::cout << "字符串连接后 " << Path << std::endl;
	char PATH[256] = "START ";
	strcat_s(PATH, Path);
	std::cout << PATH << std::endl;
	//只要exe是放在ANYTOOL文件下,工具位置不做更改,都能准确运行需要的功能
	if (system(PATH) == 0)
	{
		std::cout << "低轨道粒子炮启动成功！" << std::endl;
		return 0;
	}
	return -1;
}

int FUNCTION::Begined_TCP_DDOSAttack(CString IP, CString Port, CString Thread)
{
	std::cout << MAIN::CString_To_ConstChar(IP) << std::endl;
	std::cout << MAIN::CString_To_ConstChar(Port) << std::endl;
	std::cout << MAIN::CString_To_ConstChar(Thread) << std::endl;

	int port = 0;
	int thread = 0;
	port = atoi(MAIN::CString_To_ConstChar(Port));
	thread = atoi(MAIN::CString_To_ConstChar(Thread));

	if (!Init_CSharP_DLL_To_CPlusPlus_DLL(MAIN::CString_To_ConstChar(IP),
		port,
		thread))
	{
		std::cout << "攻击成功!" << std::endl;
		m_ISDDOS = 1;
		return 0;
	}
	return -1;
}

int FUNCTION::Ended_TCP_DDOSAttack()
{
	if (m_ISDDOS == 1)
	{
		Stop_CSharP_DLL_To_CPlusPlus_DLL_DDosAttack();
		return 0;
	}
	return -1;
}

int FUNCTION::PasswordManager()
{
	char Path[256] = { 0 };
	MAIN::GetCur_ExeRunPath(Path, sizeof(Path));
	const char *PasswordManager = "\\ANYTOOL\\Tool\\PasswordManager\\PasswordManager.exe";//工具位置,不可更改
	std::cout << "字符串未连接前 " << Path << std::endl;
	strcat_s(Path, PasswordManager);
	std::cout << "字符串连接后 " << Path << std::endl;
	char PATH[256] = "START ";
	strcat_s(PATH, Path);
	std::cout << PATH << std::endl;
	//只要exe是放在ANYTOOL文件下,工具位置不做更改,都能准确运行需要的功能
	if (system(PATH) == 0)
	{
		std::cout << "PasswordManager启动成功！" << std::endl;
		return 0;
	}
	return -1;
}

void FUNCTION::Get_ComputerIP()
{
	char buf[256] = "";
	hostent *ph = NULL;
	WSADATA w;
	WSAStartup(0x0101, &w);//这一行必须在使用任何SOCKET函数前写！


	gethostname(buf, 256);
	std::string hostName = buf;//此处获得本机名称

	ph = gethostbyname(buf);

	int i = 0;
	while (ph->h_addr_list[i] != NULL)
	{
		printf("COMPUTER NAME : %s\n", ph->h_name);
		printf("COMPUTER     IP ： %s\n", inet_ntoa(*((struct in_addr *)ph->h_addr_list[i])));
		i++;
	}
	const char *IP = inet_ntoa(*((struct in_addr *)ph->h_addr_list[i - 1]));//此处获得本机IP
	int MessageBoxAValue = MessageBoxA(NULL, IP, "MessageBoxA", MB_OK);
	printf("MessageBoxAValue = %d\n", MessageBoxAValue);

	WSACleanup();
}

void FUNCTION::Get_ComputerName()
{
	char buf[256] = "";
	hostent *ph = NULL;
	WSADATA w;
	WSAStartup(0x0101, &w);//这一行必须在使用任何SOCKET函数前写！


	gethostname(buf, 256);
	std::string hostName = buf;//此处获得本机名称

	int MessageBoxAValue = MessageBoxA(NULL, hostName.c_str(), "MessageBoxA", MB_OK);
	printf("MessageBoxAValue = %d\n", MessageBoxAValue);
}

void FUNCTION::SoundRecording()
{
	char Path[256] = { 0 };
	MAIN::GetCur_ExeRunPath(Path, sizeof(Path));
	const char *SoundRecording = "\\ANYTOOL\\Tool\\SoundRecording\\svr\\wadfngrv.exe";//工具位置,不可更改
	std::cout << "字符串未连接前 " << Path << std::endl;
	strcat_s(Path, SoundRecording);
	std::cout << "字符串连接后 " << Path << std::endl;
	char PATH[256] = "START ";
	strcat_s(PATH, Path);
	std::cout << PATH << std::endl;
	//只要exe是放在ANYTOOL文件下,工具位置不做更改,都能准确运行需要的功能
	if (system(PATH) == 0)
	{
		std::cout << "SoundRecording启动成功！" << std::endl;
	}
}


bool FUNCTION::ChangeExeIcon(LPWSTR IconFile, LPWSTR ExeFile)
{
	ICONDIRENTRY stIDE;//Icon信息
	ICONDIR stID;//Icon目录
	GRPICONDIR stGID;//GrpIcon目录
	HANDLE hFile;//文件句柄
	DWORD nSize = 0;
	DWORD nGSize = 0;
	DWORD dwReserved = 0;
	HANDLE hUpdate;//要更新文件的句柄
	PBYTE pIcon, pGrpIcon;
	BOOL ret;
	//创建文件,得到ICON的文件句柄
	hFile = CreateFileW(IconFile, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	//初始化
	ZeroMemory(&stID, sizeof(ICONDIR));
	//读文件,从文件句柄中读取到icon目录中
	ret = ReadFile(hFile, &stID, sizeof(ICONDIR), &dwReserved, NULL);
	//初始化
	ZeroMemory(&stIDE, sizeof(ICONDIRENTRY));
	//读文件,从文件句柄中读取到icon信息中
	ret = ReadFile(hFile, &stIDE, sizeof(ICONDIRENTRY), &dwReserved, NULL);

	nSize = stIDE.dwBytesInRes;
	pIcon = (PBYTE)malloc(nSize);
	//设置文件指针
	//stIDE.dwImageOffset 偏移量
	SetFilePointer(hFile, stIDE.dwImageOffset, NULL, FILE_BEGIN);
	//读文件
	ret = ReadFile(hFile, (LPVOID)pIcon, nSize, &dwReserved, NULL);
	if (!ret)
	{
		CloseHandle(hFile);
		return false;
	}
	//初始化
	ZeroMemory(&stGID, sizeof(GRPICONDIR));
	stGID.idCount = stID.idCount;
	stGID.idReserved = 0;
	stGID.idType = 1;
	CopyMemory(&stGID.idEntries, &stIDE, 12);
	stGID.idEntries.nID = 0;
	nGSize = sizeof(GRPICONDIR);
	pGrpIcon = (PBYTE)malloc(nGSize);
	CopyMemory(pGrpIcon, &stGID, nGSize);

	//得到要更新文件的句柄
	hUpdate = BeginUpdateResourceW(ExeFile, FALSE);//false 为不删除现有的资源
	//更新资源,Icon 的目录信息
	ret = UpdateResourceW(hUpdate, RT_GROUP_ICON, MAKEINTRESOURCE(1), 0, (LPVOID)pGrpIcon, nGSize);
	//更新资源
	ret = UpdateResourceW(hUpdate, RT_ICON, MAKEINTRESOURCE(1), 0, (LPVOID)pIcon, nSize);
	//结束更新资源
	EndUpdateResourceW(hUpdate, FALSE);
	if (!ret)
	{
		CloseHandle(hFile);
		return false;
	}


	CloseHandle(hFile);
	free(pGrpIcon);
	free(pIcon);
	pIcon = NULL;
	pGrpIcon = NULL;
	return true;
}

bool FUNCTION::Find_EXE_ChangeFileIcon(const char *Path, const char *Type, const wchar_t *IconName)
{
	LPWSTR File_IconName = (LPWSTR)IconName;
	WIN32_FIND_DATAA FindFileData;
	char PATH[MAX_PATH] = { 0 };
	strcat_s(PATH, Path);
	strcat_s(PATH, Type);
	HANDLE HFinder = FindFirstFileA(PATH, &FindFileData);
	if (HFinder == INVALID_HANDLE_VALUE)
	{
		std::cout << "未成功！" << std::endl;
	}
	while (true)
	{
		//是否是我们需要的文件
		if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			char EXEPath[MAX_PATH] = { 0 };
			//这里用一用字符串连接等
			char Buf[MAX_PATH] = { 0 };
			strcpy_s(Buf, Path);
			strcat_s(Buf, "%s");
			sprintf_s(EXEPath, Buf, FindFileData.cFileName);
			int Lenth = 0;
			while (EXEPath[Lenth]) { Lenth++; }
			wchar_t EXE[MAX_PATH] = { 0 };
			for (int i = 0; i < Lenth; i++)
			{
				EXE[i] = EXEPath[i];
			}
			bool ok = MAIN::ChangeExeIcon(File_IconName, (LPWSTR)EXE);
		}
		if (!(FindNextFileA(HFinder, &FindFileData)))
		{
			break;
		}
	}
	FindClose(HFinder);
	return true;
}//	FindFile("Exe\\","*.exe", L"Bitmap.ico");

WORD FUNCTION::MakeLangID()
{
	return  (SUBLANG_ENGLISH_US << 10) | LANG_ENGLISH;
}

void FUNCTION::ChangeIcon(const char* szFileName, const char* szIconFile)
{

	int i, FileGrpSize;
	DWORD dwFileSize, dwBytesRead;
	void * filemem, *p;
	PIconResDirGrp FileGrp;
	HANDLE hFile, hUpdateRes;
	const char*   szResName = "AyIcon";
	WCHAR   szFileNameWCHAR[MAX_PATH] = { 0 };
	WCHAR   szIconFileWCHAR[MAX_PATH] = { 0 };
	WCHAR   szResNameWCHAR[MAX_PATH] = { 0 };

	MultiByteToWideChar(CP_ACP, 0, szFileName, -1,
		szFileNameWCHAR, sizeof(szFileNameWCHAR));

	MultiByteToWideChar(CP_ACP, 0, szIconFile, -1,
		szIconFileWCHAR, sizeof(szIconFileWCHAR));

	MultiByteToWideChar(CP_ACP, 0, szResName, -1,
		szResNameWCHAR, sizeof(szResNameWCHAR));

	// open the icon file    
	hFile = CreateFile(szIconFileWCHAR, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(0, L"Failed open Icon File!", NULL, 0);
		return;
	}

	// get the file size     
	dwFileSize = GetFileSize(hFile, NULL);

	filemem = malloc(dwFileSize);

	// read file to memory       
	ReadFile(hFile, filemem, dwFileSize, &dwBytesRead, NULL);

	CloseHandle(hFile);


	// assume the TIconResDirGrp STRUCT     　
	FileGrp = PIconResDirGrp(filemem);

	// get Icon_Header size    
	FileGrpSize = sizeof(TIconResDirGrp) + (FileGrp->idHeader.idCount - 1)
		* sizeof(TResDirHeader);

	// begin to change the resource    
	hUpdateRes = BeginUpdateResource(szFileNameWCHAR, false);

	// change all frames'resource     
	for (i = 0; i < FileGrp->idHeader.idCount; i++)
	{

		p = (void *)((DWORD)filemem + FileGrp->idEntries[i].lImageOffset);

		// change every frame         
		UpdateResource(hUpdateRes, RT_ICON,
			MAKEINTRESOURCE(FileGrp->idEntries[i].lImageOffset)
			, MAIN::MakeLangID(), p, FileGrp->idEntries[i].lBYTEsInRes);
	}

	// update header information  
	UpdateResource(hUpdateRes, RT_GROUP_ICON, szResNameWCHAR, MAIN::MakeLangID(),
		FileGrp, FileGrpSize);

	EndUpdateResource(hUpdateRes, false);
	free(filemem);
	filemem = NULL;
}




//===================================================
CString FUNCTION::CreateCFileDialog()
{
	CFileDialog CFileDialog(TRUE, NULL, NULL, 0, (LPCTSTR)_TEXT("视频文件(*.mp4)|*.mp4|所有文件(*.*)|*.*||"));

	if (CFileDialog.DoModal() == IDOK)
	{
		return CFileDialog.GetPathName();
	}
	return NULL;
}

void FUNCTION::EditVideoBecomeFrame(CString VideoPathName, CString ImageType, CString FrameNumber)
{
	std::cout << "要剪辑的视频 " << MAIN::CString_To_ConstChar(VideoPathName) << std::endl;
	std::cout << "图片类型 " << MAIN::CString_To_ConstChar(ImageType) << std::endl;
	std::cout << "每秒帧数 " << MAIN::CString_To_ConstChar(FrameNumber) << std::endl;

	std::string Video = MAIN::CString_To_String(VideoPathName);
	std::string Type = MAIN::CString_To_String(ImageType);
	std::string FrameNum = MAIN::CString_To_String(FrameNumber);

	char EXERunPath[1024] = { 0 };
	char StartRuning[256] = " -i ";
	char StartType[256] = " -r ";
	char Vcodec[256] = " -vcodec ";
	char FramePath[256] = " ";
	char EditVideoFramePath[256] = "\\ANYTOOL\\Tool\\VideoTranslates\\Image\\%04d.";
	char Ffmpeg[256] = "\\ANYTOOL\\Tool\\VideoTranslates\\ffmpeg-20160425-git-9ac154d-win32-static\\bin\\ffmpeg.exe ";
	strcat_s(EditVideoFramePath, Type.c_str());//帧的相对路径
	MAIN::GetCur_ExeRunPath(EXERunPath,sizeof(EXERunPath));
	strcat_s(FramePath, EXERunPath);//帧的缓存绝对目录
	strcat_s(FramePath, EditVideoFramePath);//帧的缓存绝对路径

	strcat_s(StartRuning, Video.c_str());//命令到视频路径
	strcat_s(StartType, FrameNum.c_str());//帧数
	strcat_s(StartType, Vcodec);//命令
	strcat_s(StartType,Type.c_str());//图片类型
	strcat_s(StartRuning, StartType);//视频路径到连接帧数和帧类型

	strcat_s(EXERunPath, Ffmpeg); //exe绝对路径
	strcat_s(EXERunPath, StartRuning);//连接剪辑
	strcat_s(EXERunPath, FramePath); //连接缓存目录
	std::cout << "最终运行的命令 " << EXERunPath << std::endl;

	//只要exe是放在ANYTOOL文件下,工具位置不做更改,都能准确运行需要的功能
	if (system(EXERunPath) == 0)
	{
		char PathFile[256] = "START ";
		const char *EditVideoFrameDir = "\\ANYTOOL\\Tool\\VideoTranslates\\Image";
		MAIN::GetCur_ExeRunPath(EXERunPath, sizeof(EXERunPath));
		strcat_s(PathFile, EXERunPath);
		strcat_s(PathFile, EditVideoFrameDir);
		std::cout << "视频到帧启动完成！" << std::endl;
		if (system(PathFile) == 0)
		{
			std::cout << "视频到帧执行完毕！" << std::endl;
		}
	}
}

void FUNCTION::PlayFrameAnimation(CDC *pCDC)
{
	static int TimeValue = 0;


	CDC mdc;
	mdc.CreateCompatibleDC(pCDC);
	char Image[256] = { 0 };
	sprintf_s(Image, "Tool\\VideoTranslates\\Image\\%04d.bmp", TimeValue + 1);
	HBITMAP bmp = (HBITMAP)LoadImageA(NULL, Image, IMAGE_BITMAP, 600, 500, LR_LOADFROMFILE);//A为char*
	if (bmp)
	{
		SelectObject(mdc, bmp);

		pCDC->BitBlt(4, 50, 550, 500, &mdc, 0, 0, SRCCOPY);

		DeleteObject(bmp);
		DeleteDC(mdc);
	}


	TimeValue++;
}

void FUNCTION::PlayerMusic()
{
	MUSIC->Init();

	CFileDialog CFileDialog(TRUE, NULL, NULL, 0, (LPCTSTR)_TEXT("音乐文件(*.mp3)|*.mp3|所有文件(*.*)|*.*||"));

	if (CFileDialog.DoModal() == IDOK)
	{
		MUSIC->LoadMusic(MAIN::CString_To_String(CFileDialog.GetPathName()));
		MUSIC->PlayMusic(MAIN::CString_To_String(CFileDialog.GetPathName()));
	}
}








//===================================================
//SETTIME_BEGIN_DDOS
void FUNCTION::SOCKETDDOS(CString IP, UINT Port)
{
	CSocket socket;
	socket.Create();

	if (socket.Connect(IP, Port))
	{
		char buf[200] = { 0 };
		srand(GetTickCount());
		for (int i = 0; i < 200; i++)
		{
			buf[i] = rand() % 128;
		}
		socket.Send(buf, 200);
	}
	socket.Close();
	//DOS S;
	//S.Run();
}