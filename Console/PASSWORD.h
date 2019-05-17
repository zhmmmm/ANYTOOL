#pragma once
#include <iostream>
#include <Windows.h>
#include <assert.h>
#include <stdio.h>


#define DELETEACCOUNT       0//删除整个账号
#define DELETEPASSWORD     1//删除密码
#define DELETEINFO                 2//删除信息

typedef struct PASS_WORD
{
	unsigned int DataHeadLenght = 0;//一个数据的信息头长
	unsigned long AccoundLenght = 0;//账号长度
	unsigned long PasswordLenght = 0;//密码长度
	long long UserInfoLenght = 0;//信息长度
	//四个字节的换行
}Pass_word, *LPPassword;

typedef struct USERINFO
{
	char Account[256] = { 0 };
	char Password[256] = { 0 };
	char UserInfo[1024] = { 0 };
}UserInfo, *LPUserInfo;

class PASSWORD
{
	char m_FileName[256] = "Text";

	char m_EncryptionInfo[1024] = { };//加密数据信息
	UserInfo *m_DATAINFO = NULL;//用户信息表
	int m_UserNum = 0;//账号数量
public:
	//在创建对象时,会遍历所有的数据到内存中
	PASSWORD();
	~PASSWORD();

	//相当于刷新内存中的数据
	void InitData();
	//增 成功返回TRUE
	BOOL SaveData(const char *Account, const char *Password, const char *Info = NULL);
	BOOL SaveData(UserInfo UserData);

	//删 成功返回TRUE
	BOOL DeleteData(const char *Account, int DEFINE);

	//查改
	void GetDataPassword(const char *Account, char *PasswordBuf);
	char *GetDataPassword(const char *Account);
	BOOL SetDataPassword(const char *Account, const char *Password);

	BOOL SetDataInfo(const char *Account, const char *Info);
	void GetDataInfo(const char *Account, char *DataInfoBuf);
	char *GetDataInfo(const char *Account);

	BOOL SetDataAccount(const char *Account, const char *Accounts);



	//删除用户信息列表
	void DeleteUserDataInfoList();

	//清除文件内容
	void ClearFileContent();
	int GetUserNum() { return m_UserNum; };
	UserInfo *GetDATAINFO() { return m_DATAINFO; };
private:
	//追加的方式打开
	FILE *OpenFile_Write();
	//以必须有文件的二进制模式打开
	FILE *OpenFile_Read();

	//打开文件结束
	void OpenFile_End(FILE *File);
	void Clear(const char *FileName);
	void Assert(void *Pointer);
	void DeleteMemory();

	//账号是否存在
	BOOL IsExistence(const char *Account, FILE *File);
	//字符串比较 相同返回TRUE
	BOOL StringCompare(const char *Str_1, const char *Str_2);
	//空信息加密
	//信息为空,还是存在信息头的四个字节
	BOOL NULL_Encryption(const char *Info);
	//遍历文件所有信息
	void ErgodicFileAnyInfo();
	//删除某个账号的所有信息
	BOOL DeleteAccount(const char *Account);
	//删除某账号的密码
	BOOL DeleteAccountPassword(const char *Account);
	//删除某账号的信息
	BOOL DeleteAccountInfo(const char *Account);

	//写入缓存中的数据
	void InsertData(FILE *File);
	void InsertData();
	//加密数据
	void Encryption(const char *AnyInfo);
	//解密数据
	void Decode(char *EncryptionInfo, char *Buf);
	//写入加密数据
	void WriteEncryptionInfo(FILE *File);
};


class PASSENGINE
{
	PASSWORD *m_PW = new PASSWORD();


	char m_Password[256] = { 0 };
	bool m_ImportPasswordOk = false;
	int m_Code = 0;
	bool m_PassOk = false;
	char m_EncryptionInfo[1024] = { };//加密数据信息
	const char *FileName = "PASSWORD";
public:
	PASSENGINE();
	~PASSENGINE();
	void Run();
private:
	bool EnterPassword();
	void Get_Password();
	void Set_Password(FILE *File);
protected:
	void _Password();
	char _Pass_word[256] = "themyqq321";
	void _Print();
	void _SwitchCode(int Code);

	void _SaveAccount();
	void _DeleteAccount();
	void _ChangeAccount();
	void _ChangePassword();
	void _ChangeUserInfo();
};
