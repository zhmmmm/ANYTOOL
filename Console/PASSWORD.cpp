#include "PASSWORD.h"

//在创建对象时,会遍历所有的数据到内存中
PASSWORD::PASSWORD()
{
	PASSWORD::ErgodicFileAnyInfo();
}

PASSWORD::~PASSWORD()
{
	PASSWORD::DeleteUserDataInfoList();
}

//相当于刷新内存中的数据
void PASSWORD::InitData()
{
	PASSWORD::ErgodicFileAnyInfo();
}

BOOL PASSWORD::SaveData(const char *Account, const char *Password, const char *Info)
{
	PASSWORD::Assert((void*)Account);
	PASSWORD::Assert((void*)Password);


	FILE *File = PASSWORD::OpenFile_Write();

	//如果账号不存在
	if (IsExistence(Account, File) == FALSE)
	{
		Pass_word PW;
		PW.AccoundLenght = strlen(Account);
		PW.DataHeadLenght = sizeof(Pass_word);
		PW.PasswordLenght = strlen(Password);
		if (Info)
		{
			PW.UserInfoLenght = strlen(Info);
		}
		else
		{
			PW.UserInfoLenght = 0;
		}
		fwrite(&PW, PW.DataHeadLenght, 1, File);

		PASSWORD::Encryption(Account);
		PASSWORD::WriteEncryptionInfo(File);
		PASSWORD::Encryption(Password);
		PASSWORD::WriteEncryptionInfo(File);
		PASSWORD::NULL_Encryption(Info);
		PASSWORD::WriteEncryptionInfo(File);

		PASSWORD::OpenFile_End(File);
		return TRUE;
	}
	else//账号存在
	{
		printf("账号:%s 已经存在,保存失败,如何要更改信息或者密码,请用其他命令!\n", Account);
	}
	PASSWORD::OpenFile_End(File);
	return FALSE;
}

BOOL PASSWORD::SaveData(UserInfo UserData)
{
	return PASSWORD::SaveData(UserData.Account, UserData.Password, UserData.UserInfo);
}

BOOL PASSWORD::DeleteData(const char *Account, int DEFINE)
{
	PASSWORD::Assert((void*)Account);

	switch (DEFINE)
	{
	case DELETEACCOUNT:
	{
		return PASSWORD::DeleteAccount(Account);
	}; break;
	case DELETEPASSWORD:
	{
		return PASSWORD::DeleteAccountPassword(Account);
	}; break;
	case DELETEINFO:
	{
		return PASSWORD::DeleteAccountInfo(Account);
	}; break;
	}
	return FALSE;
}

void PASSWORD::GetDataPassword(const char *Account, char *PasswordBuf)
{
	PASSWORD::Assert((void*)Account);

	FILE *File = PASSWORD::OpenFile_Read();

	//如果账号存在
	if (IsExistence(Account, File))
	{
		Pass_word PW;
		char EncryptionInfo[256] = { 0 };
		int AccountLen = 0;
		int PasswordLen = 0;
		long Offset = 0;
		char Buf[256] = { 0 };

		while (true)
		{
			ZeroMemory(&PW, sizeof(Pass_word));
			ZeroMemory(EncryptionInfo, sizeof(EncryptionInfo));
			ZeroMemory(&AccountLen, sizeof(int));
			ZeroMemory(&PasswordLen, sizeof(int));
			ZeroMemory(&Offset, sizeof(long));
			ZeroMemory(Buf, sizeof(Buf));

			fread_s(&PW, sizeof(Pass_word), sizeof(Pass_word), 1, File);
			//数据头 账号 密码
			if (PW.DataHeadLenght == 0 || PW.AccoundLenght == 0)
			{
				PASSWORD::OpenFile_End(File);
				return;
			}

			//账号长度匹配
			fread_s(&AccountLen, sizeof(int), sizeof(int), 1, File);
			if (AccountLen != PW.AccoundLenght)
			{
				printf("数据有误\n");
				PASSWORD::OpenFile_End(File);
				return;
			}
			//密码长度匹配
			fseek(File, PW.AccoundLenght, SEEK_CUR);
			fread_s(&PasswordLen, sizeof(int), sizeof(int), 1, File);
			if (PasswordLen != PW.PasswordLenght)
			{
				printf("密码数据有误\n");
				PASSWORD::OpenFile_End(File);
				return;
			}

			//退到账号信息头的前面
			Offset = sizeof(int) + PW.AccoundLenght + sizeof(int);
			fseek(File, -Offset, SEEK_CUR);
			fread_s(EncryptionInfo, sizeof(EncryptionInfo), PW.AccoundLenght + sizeof(int), 1, File);

			//解密数据
			PASSWORD::Decode(EncryptionInfo, Buf);

			//账号匹配
			if (PASSWORD::StringCompare(Account, Buf) == TRUE)
			{
				int PasswordLen = 0;
				fread_s(&PasswordLen, sizeof(int), sizeof(int), 1, File);
				if (PasswordLen != PW.PasswordLenght)
				{
					printf("数据有误\n");
					PASSWORD::OpenFile_End(File);
					return;
				}
				ZeroMemory(EncryptionInfo, sizeof(EncryptionInfo));
				Offset = sizeof(int);
				fseek(File, -Offset, SEEK_CUR);
				fread_s(EncryptionInfo, sizeof(EncryptionInfo), PasswordLen + sizeof(int), 1, File);
				PASSWORD::Decode(EncryptionInfo, PasswordBuf);

				PASSWORD::OpenFile_End(File);
				return;
			}

			//跳过这个账号读取下一个账号
			int TempVar = sizeof(int) * 2;
			fseek(File, (long)(PW.PasswordLenght + TempVar + PW.UserInfoLenght), SEEK_CUR);
		}
	}
	else
	{
		printf("账号不存在！");
	}

	PASSWORD::OpenFile_End(File);
}

char *PASSWORD::GetDataPassword(const char *Account)
{
	PASSWORD::Assert((void*)Account);

	FILE *File = PASSWORD::OpenFile_Read();

	//如果账号存在
	if (IsExistence(Account, File))
	{
		Pass_word PW;
		char EncryptionInfo[256] = { 0 };
		int AccountLen = 0;
		int PasswordLen = 0;
		long Offset = 0;
		char Buf[256] = { 0 };

		while (true)
		{
			ZeroMemory(&PW, sizeof(Pass_word));
			ZeroMemory(EncryptionInfo, sizeof(EncryptionInfo));
			ZeroMemory(&AccountLen, sizeof(int));
			ZeroMemory(&PasswordLen, sizeof(int));
			ZeroMemory(&Offset, sizeof(long));
			ZeroMemory(Buf, sizeof(Buf));

			fread_s(&PW, sizeof(Pass_word), sizeof(Pass_word), 1, File);
			//数据头 账号 密码
			if (PW.DataHeadLenght == 0 || PW.AccoundLenght == 0)
			{
				PASSWORD::OpenFile_End(File);
				return NULL;
			}

			//账号长度匹配
			fread_s(&AccountLen, sizeof(int), sizeof(int), 1, File);
			if (AccountLen != PW.AccoundLenght)
			{
				printf("数据有误\n");
				PASSWORD::OpenFile_End(File);
				return NULL;
			}
			//密码长度匹配
			fseek(File, PW.AccoundLenght, SEEK_CUR);
			fread_s(&PasswordLen, sizeof(int), sizeof(int), 1, File);
			if (PasswordLen != PW.PasswordLenght)
			{
				printf("密码数据有误\n");
				PASSWORD::OpenFile_End(File);
				return NULL;
			}

			//退到账号信息头的前面
			Offset = sizeof(int) + PW.AccoundLenght + sizeof(int);
			fseek(File, -Offset, SEEK_CUR);
			fread_s(EncryptionInfo, sizeof(EncryptionInfo), PW.AccoundLenght + sizeof(int), 1, File);

			//解密数据
			PASSWORD::Decode(EncryptionInfo, Buf);

			//账号匹配
			if (PASSWORD::StringCompare(Account, Buf) == TRUE)
			{
				int PasswordLen = 0;
				fread_s(&PasswordLen, sizeof(int), sizeof(int), 1, File);
				if (PasswordLen != PW.PasswordLenght)
				{
					printf("数据有误\n");
					PASSWORD::OpenFile_End(File);
					return NULL;
				}
				ZeroMemory(EncryptionInfo, sizeof(EncryptionInfo));
				Offset = sizeof(int);
				fseek(File, -Offset, SEEK_CUR);
				fread_s(EncryptionInfo, sizeof(EncryptionInfo), PasswordLen + sizeof(int), 1, File);
				static char PasswordBuf[256] = { 0 };
				PASSWORD::Decode(EncryptionInfo, PasswordBuf);

				PASSWORD::OpenFile_End(File);
				return PasswordBuf;
			}

			//跳过这个账号读取下一个账号
			int TempVar = sizeof(int) * 2;
			fseek(File, (long)(PW.PasswordLenght + TempVar + PW.UserInfoLenght), SEEK_CUR);
		}
	}
	else
	{
		printf("账号不存在！\n");
	}

	PASSWORD::OpenFile_End(File);
	return NULL;
}

BOOL PASSWORD::SetDataPassword(const char *Account, const char *Password)
{
	PASSWORD::Assert((void*)Account);
	PASSWORD::Assert((void*)Password);

	FILE *File = PASSWORD::OpenFile_Read();

	//如果账号存在
	if (IsExistence(Account, File))
	{
		for (int i = 0; i < m_UserNum; i++)
		{
			if (PASSWORD::StringCompare(m_DATAINFO[i].Account, Account))
			{
				ZeroMemory(m_DATAINFO[i].Password, sizeof(m_DATAINFO[i].Password));
				int TempLen = 0;
				while (Password[TempLen]) { TempLen++; }
				memcpy_s(m_DATAINFO[i].Password, sizeof(m_DATAINFO[i].Password), Password, TempLen);
				break;
			}
		}
	}
	else
	{
		printf("账号不存在！");
		PASSWORD::OpenFile_End(File);
		return FALSE;
	}

	PASSWORD::OpenFile_End(File);

	//写入缓存中的数据
	PASSWORD::InsertData();
	return TRUE;
}

BOOL PASSWORD::SetDataInfo(const char *Account, const char *Info)
{
	PASSWORD::Assert((void*)Account);
	PASSWORD::Assert((void*)Info);

	FILE *File = PASSWORD::OpenFile_Read();

	//如果账号存在
	if (IsExistence(Account, File))
	{
		for (int i = 0; i < m_UserNum; i++)
		{
			if (PASSWORD::StringCompare(m_DATAINFO[i].Account, Account))
			{
				ZeroMemory(m_DATAINFO[i].UserInfo, sizeof(m_DATAINFO[i].UserInfo));
				int TempLen = 0;
				while (Info[TempLen]) { TempLen++; }
				memcpy_s(m_DATAINFO[i].UserInfo, sizeof(m_DATAINFO[i].UserInfo), Info, TempLen);
				break;
			}
		}
	}
	else
	{
		printf("账号不存在！\n");
		PASSWORD::OpenFile_End(File);
		return FALSE;
	}

	PASSWORD::OpenFile_End(File);

	//写入缓存中的数据
	PASSWORD::InsertData();
	return TRUE;
}

void PASSWORD::GetDataInfo(const char *Account, char *DataInfoBuf)
{
	PASSWORD::Assert((void*)Account);

	FILE *File = PASSWORD::OpenFile_Read();

	//如果账号存在
	if (IsExistence(Account, File))
	{
		Pass_word PW;
		char EncryptionInfo[256] = { 0 };
		int AccountLen = 0;
		int PasswordLen = 0;
		long Offset = 0;
		char Buf[256] = { 0 };

		while (true)
		{
			ZeroMemory(&PW, sizeof(Pass_word));
			ZeroMemory(EncryptionInfo, sizeof(EncryptionInfo));
			ZeroMemory(&AccountLen, sizeof(int));
			ZeroMemory(&PasswordLen, sizeof(int));
			ZeroMemory(&Offset, sizeof(long));
			ZeroMemory(Buf, sizeof(Buf));

			fread_s(&PW, sizeof(Pass_word), sizeof(Pass_word), 1, File);
			//数据头 账号 密码
			if (PW.DataHeadLenght == 0 || PW.AccoundLenght == 0)
			{
				PASSWORD::OpenFile_End(File);
				return;
			}

			//账号长度匹配
			fread_s(&AccountLen, sizeof(int), sizeof(int), 1, File);
			if (AccountLen != PW.AccoundLenght)
			{
				printf("数据有误\n");
				PASSWORD::OpenFile_End(File);
				return;
			}
			//密码长度匹配
			fseek(File, PW.AccoundLenght, SEEK_CUR);
			fread_s(&PasswordLen, sizeof(int), sizeof(int), 1, File);
			if (PasswordLen != PW.PasswordLenght)
			{
				printf("密码数据有误\n");
				PASSWORD::OpenFile_End(File);
				return;
			}

			//退到账号信息头的前面
			Offset = sizeof(int) + PW.AccoundLenght + sizeof(int);
			fseek(File, -Offset, SEEK_CUR);
			fread_s(EncryptionInfo, sizeof(EncryptionInfo), PW.AccoundLenght + sizeof(int), 1, File);

			//解密数据
			PASSWORD::Decode(EncryptionInfo, Buf);

			//账号匹配
			if (PASSWORD::StringCompare(Account, Buf) == TRUE)
			{
				int PasswordLen = 0;
				fread_s(&PasswordLen, sizeof(int), sizeof(int), 1, File);
				if (PasswordLen != PW.PasswordLenght)
				{
					printf("数据有误\n");
					PASSWORD::OpenFile_End(File);
					return;
				}
				ZeroMemory(EncryptionInfo, sizeof(EncryptionInfo));
				fseek(File, PW.PasswordLenght, SEEK_CUR);
				int DataInfoLen = 0;
				fread_s(&DataInfoLen, sizeof(DataInfoLen), sizeof(int), 1, File);
				if (DataInfoLen != PW.UserInfoLenght)
				{
					printf("数据有误\n");
					PASSWORD::OpenFile_End(File);
					return;
				}
				Offset = sizeof(int);
				fseek(File, -Offset, SEEK_CUR);
				fread_s(&EncryptionInfo, sizeof(EncryptionInfo), (size_t)(PW.UserInfoLenght + (long long)sizeof(int)), 1, File);
				PASSWORD::Decode(EncryptionInfo, DataInfoBuf);

				PASSWORD::OpenFile_End(File);
				return;
			}

			//跳过这个账号读取下一个账号
			int TempVar = sizeof(int) * 2;
			fseek(File, (long)(PW.PasswordLenght + TempVar + PW.UserInfoLenght), SEEK_CUR);
		}
	}
	else
	{
		printf("账号不存在！");
	}

	PASSWORD::OpenFile_End(File);
}

char *PASSWORD::GetDataInfo(const char *Account)
{
	PASSWORD::Assert((void*)Account);

	FILE *File = PASSWORD::OpenFile_Read();

	//如果账号存在
	if (IsExistence(Account, File))
	{
		Pass_word PW;
		char EncryptionInfo[256] = { 0 };
		int AccountLen = 0;
		int PasswordLen = 0;
		long Offset = 0;
		char Buf[256] = { 0 };

		while (true)
		{
			ZeroMemory(&PW, sizeof(Pass_word));
			ZeroMemory(EncryptionInfo, sizeof(EncryptionInfo));
			ZeroMemory(&AccountLen, sizeof(int));
			ZeroMemory(&PasswordLen, sizeof(int));
			ZeroMemory(&Offset, sizeof(long));
			ZeroMemory(Buf, sizeof(Buf));

			fread_s(&PW, sizeof(Pass_word), sizeof(Pass_word), 1, File);
			//数据头 账号 密码
			if (PW.DataHeadLenght == 0 || PW.AccoundLenght == 0)
			{
				PASSWORD::OpenFile_End(File);
				return NULL;
			}

			//账号长度匹配
			fread_s(&AccountLen, sizeof(int), sizeof(int), 1, File);
			if (AccountLen != PW.AccoundLenght)
			{
				printf("数据有误\n");
				PASSWORD::OpenFile_End(File);
				return NULL;
			}
			//密码长度匹配
			fseek(File, PW.AccoundLenght, SEEK_CUR);
			fread_s(&PasswordLen, sizeof(int), sizeof(int), 1, File);
			if (PasswordLen != PW.PasswordLenght)
			{
				printf("密码数据有误\n");
				PASSWORD::OpenFile_End(File);
				return NULL;
			}

			//退到账号信息头的前面
			Offset = sizeof(int) + PW.AccoundLenght + sizeof(int);
			fseek(File, -Offset, SEEK_CUR);
			fread_s(EncryptionInfo, sizeof(EncryptionInfo), PW.AccoundLenght + sizeof(int), 1, File);

			//解密数据
			PASSWORD::Decode(EncryptionInfo, Buf);

			//账号匹配
			if (PASSWORD::StringCompare(Account, Buf) == TRUE)
			{
				int PasswordLen = 0;
				fread_s(&PasswordLen, sizeof(int), sizeof(int), 1, File);
				if (PasswordLen != PW.PasswordLenght)
				{
					printf("数据有误\n");
					PASSWORD::OpenFile_End(File);
					return NULL;
				}
				ZeroMemory(EncryptionInfo, sizeof(EncryptionInfo));
				fseek(File, PW.PasswordLenght, SEEK_CUR);
				int DataInfoLen = 0;
				fread_s(&DataInfoLen, sizeof(DataInfoLen), sizeof(int), 1, File);
				if (DataInfoLen != PW.UserInfoLenght)
				{
					printf("数据有误\n");
					PASSWORD::OpenFile_End(File);
					return NULL;
				}
				Offset = sizeof(int);
				fseek(File, -Offset, SEEK_CUR);
				fread_s(&EncryptionInfo, sizeof(EncryptionInfo), (size_t)(PW.UserInfoLenght + (long long)sizeof(int)), 1, File);

				static char DataInfoBuf[256] = { 0 };
				PASSWORD::Decode(EncryptionInfo, DataInfoBuf);

				PASSWORD::OpenFile_End(File);
				return DataInfoBuf;
			}

			//跳过这个账号读取下一个账号
			int TempVar = sizeof(int) * 2;
			fseek(File, (long)(PW.PasswordLenght + TempVar + PW.UserInfoLenght), SEEK_CUR);
		}
	}
	else
	{
		printf("账号不存在！");
	}

	PASSWORD::OpenFile_End(File);
	return NULL;
}

BOOL PASSWORD::SetDataAccount(const char *Account, const char *Accounts)
{
	PASSWORD::Assert((void*)Account);
	PASSWORD::Assert((void*)Accounts);

	FILE *File = PASSWORD::OpenFile_Read();

	//如果账号存在
	if (IsExistence(Account, File))
	{
		for (int i = 0; i < m_UserNum; i++)
		{
			if (PASSWORD::StringCompare(m_DATAINFO[i].Account, Account))
			{
				ZeroMemory(m_DATAINFO[i].Account, sizeof(m_DATAINFO[i].Account));
				int TempLen = 0;
				while (Accounts[TempLen]) { TempLen++; }
				memcpy_s(m_DATAINFO[i].Account, sizeof(m_DATAINFO[i].Account), Accounts, TempLen);
				break;
			}
		}
	}
	else
	{
		printf("账号不存在！\n");
		PASSWORD::OpenFile_End(File);
		return FALSE;
	}

	PASSWORD::OpenFile_End(File);

	//写入缓存中的数据
	PASSWORD::InsertData();
	return TRUE;
}

//删除用户信息列表
void PASSWORD::DeleteUserDataInfoList()
{
	if (m_DATAINFO)
	{
		delete[] m_DATAINFO;
		m_DATAINFO = NULL;
	}
}

//加密数据
void PASSWORD::Encryption(const char *AnyInfo)
{
	PASSWORD::Assert((void*)AnyInfo);

	//数据的长
	int TempLen = strlen(AnyInfo);

	//前四个字节为数据的长
	*((int*)m_EncryptionInfo) = TempLen;
	for (int i = 0; i < TempLen; i++)
	{
		m_EncryptionInfo[i + sizeof(int)] = AnyInfo[i] + 1;
	}
}
//解密数据
void PASSWORD::Decode(char *EncryptionInfo, char *Buf)
{
	PASSWORD::Assert((void*)EncryptionInfo);
	PASSWORD::Assert((void*)Buf);

	int TempLen = *((int*)EncryptionInfo);
	for (int i = 0; i < TempLen; i++)
	{
		Buf[i] = EncryptionInfo[i + sizeof(int)] - 1;
	}
}

//账号是否存在
BOOL PASSWORD::IsExistence(const char *Account, FILE *File)
{
	PASSWORD::Assert((void*)Account);
	PASSWORD::Assert((void*)File);


	if (File)
	{
		Pass_word P_W;
		char EncryptionInfo[256] = { 0 };
		int AccountLen = 0;
		int PasswordLen = 0;
		long Offset = 0;
		char Buf[256] = { 0 };

		while (true)
		{
			ZeroMemory(&P_W, sizeof(Pass_word));
			ZeroMemory(EncryptionInfo, sizeof(EncryptionInfo));
			ZeroMemory(&AccountLen, sizeof(int));
			ZeroMemory(&PasswordLen, sizeof(int));
			ZeroMemory(&Offset, sizeof(long));
			ZeroMemory(Buf, sizeof(Buf));

			fread_s(&P_W, sizeof(Pass_word), sizeof(Pass_word), 1, File);
			//数据头 账号
			if (P_W.DataHeadLenght == 0 || P_W.AccoundLenght == 0)
			{
				return FALSE;
			}
			//账号长度匹配
			fread_s(&AccountLen, sizeof(int), sizeof(int), 1, File);
			if (AccountLen != P_W.AccoundLenght)
			{
				printf("账号数据有误\n");
				return FALSE;
			}
			//密码长度匹配
			fseek(File, P_W.AccoundLenght, SEEK_CUR);
			fread_s(&PasswordLen, sizeof(int), sizeof(int), 1, File);
			if (PasswordLen != P_W.PasswordLenght)
			{
				printf("密码数据有误\n");
				return FALSE;
			}

			//退到账号信息头的前面
			Offset = sizeof(int) + P_W.AccoundLenght + sizeof(int);
			fseek(File, -Offset, SEEK_CUR);
			fread_s(EncryptionInfo, sizeof(EncryptionInfo), P_W.AccoundLenght + sizeof(int), 1, File);

			//解密账号数据
			PASSWORD::Decode(EncryptionInfo, Buf);
			//存在这个账号
			if (PASSWORD::StringCompare(Account, Buf) == TRUE)
			{
				rewind(File);
				return TRUE;
			}
			//跳过这个账号读取下一个账号
			int TempVar = sizeof(int) * 2;
			fseek(File, (long)(P_W.PasswordLenght + TempVar + P_W.UserInfoLenght), SEEK_CUR);
		}
	}
	return FALSE;
}


//删除某个账号的所有信息
BOOL PASSWORD::DeleteAccount(const char *Account)
{
	PASSWORD::Assert((void*)Account);

	if (m_UserNum == 0)
	{
		printf("当前一个账号都没有！\n");
		return FALSE;
	}

	PASSWORD::InitData();

	FILE *File = PASSWORD::OpenFile_Read();

	//如果账号存在
	if (IsExistence(Account, File))
	{
		if (m_UserNum >= 2)
		{
			for (int i = 0; i < m_UserNum; i++)
			{
				if (PASSWORD::StringCompare(m_DATAINFO[i].Account, Account))
				{
					if (i == 0)//删除第一个
					{
						for (int j = 0; j < m_UserNum - 1; j++)
						{
							memcpy_s(&(m_DATAINFO[j]), sizeof(USERINFO), &(m_DATAINFO[j + 1]), sizeof(USERINFO));
						}
						break;
					}
					else if (i == m_UserNum - 1)//删除最后那一个
					{
						memset(&(m_DATAINFO[i]), 0, sizeof(USERINFO));
						break;
					}
					else//删除中间那一个
					{
						for (int j = i; j < m_UserNum - 1; j++)
						{
							memcpy_s(&(m_DATAINFO[j]), sizeof(USERINFO), &(m_DATAINFO[j + 1]), sizeof(USERINFO));
						}
						memset(&(m_DATAINFO[m_UserNum - 1]), 0, sizeof(USERINFO));
						break;
					}
				}
			}
		}
	}
	else
	{
		printf("账号不存在！\n");
		PASSWORD::OpenFile_End(File);
		return FALSE;
	}

	PASSWORD::OpenFile_End(File);

	PASSWORD::ClearFileContent();
	File = PASSWORD::OpenFile_Write();

	m_UserNum -= 1;
	if (m_UserNum == 0)//刚好删除的是只有一个账号
	{
		PASSWORD::OpenFile_End(File);
		PASSWORD::DeleteUserDataInfoList();
		return TRUE;
	}

	for (int i = 0; i < m_UserNum; i++)
	{
		Pass_word PW;
		PW.AccoundLenght = strlen(m_DATAINFO[i].Account);
		PW.DataHeadLenght = sizeof(Pass_word);
		PW.PasswordLenght = strlen(m_DATAINFO[i].Password);
		PW.UserInfoLenght = strlen(m_DATAINFO[i].UserInfo);
		fwrite(&PW, PW.DataHeadLenght, 1, File);

		PASSWORD::Encryption(m_DATAINFO[i].Account);
		PASSWORD::WriteEncryptionInfo(File);
		PASSWORD::Encryption(m_DATAINFO[i].Password);
		PASSWORD::WriteEncryptionInfo(File);
		PASSWORD::NULL_Encryption(m_DATAINFO[i].UserInfo);
		PASSWORD::WriteEncryptionInfo(File);
	}

	PASSWORD::OpenFile_End(File);

	PASSWORD::DeleteUserDataInfoList();
	PASSWORD::InitData();
	return TRUE;
}
//删除某账号的密码
BOOL PASSWORD::DeleteAccountPassword(const char *Account)
{
	PASSWORD::Assert((void*)Account);

	if (m_UserNum == 0)
	{
		printf("当前一个账号都没有！\n");
		return FALSE;
	}

	PASSWORD::InitData();

	FILE *File = PASSWORD::OpenFile_Read();

	//如果账号存在
	if (IsExistence(Account, File))
	{
		for (int i = 0; i < m_UserNum; i++)
		{
			if (PASSWORD::StringCompare(m_DATAINFO[i].Account, Account))
			{
				memset(m_DATAINFO[i].Password, 0, sizeof(m_DATAINFO[i].Password));
				break;
			}
		}
	}
	else
	{
		printf("账号不存在！\n");
		PASSWORD::OpenFile_End(File);
		return FALSE;
	}

	PASSWORD::OpenFile_End(File);

	PASSWORD::ClearFileContent();
	File = PASSWORD::OpenFile_Write();

	for (int i = 0; i < m_UserNum; i++)
	{
		Pass_word PW;
		PW.AccoundLenght = strlen(m_DATAINFO[i].Account);
		PW.DataHeadLenght = sizeof(Pass_word);
		PW.PasswordLenght = strlen(m_DATAINFO[i].Password);
		PW.UserInfoLenght = strlen(m_DATAINFO[i].UserInfo);
		fwrite(&PW, PW.DataHeadLenght, 1, File);

		PASSWORD::Encryption(m_DATAINFO[i].Account);
		PASSWORD::WriteEncryptionInfo(File);
		PASSWORD::Encryption(m_DATAINFO[i].Password);
		PASSWORD::WriteEncryptionInfo(File);
		PASSWORD::NULL_Encryption(m_DATAINFO[i].UserInfo);
		PASSWORD::WriteEncryptionInfo(File);
	}

	PASSWORD::OpenFile_End(File);

	PASSWORD::DeleteUserDataInfoList();
	PASSWORD::InitData();
	return TRUE;
}
//删除某账号的信息
BOOL PASSWORD::DeleteAccountInfo(const char *Account)
{
	PASSWORD::Assert((void*)Account);

	if (m_UserNum == 0)
	{
		printf("当前一个账号都没有！\n");
		return FALSE;
	}

	PASSWORD::InitData();

	FILE *File = PASSWORD::OpenFile_Read();

	//如果账号存在
	if (IsExistence(Account, File))
	{
		for (int i = 0; i < m_UserNum; i++)
		{
			if (PASSWORD::StringCompare(m_DATAINFO[i].Account, Account))
			{
				memset(m_DATAINFO[i].UserInfo, 0, sizeof(m_DATAINFO[i].UserInfo));
				break;
			}
		}
	}
	else
	{
		printf("账号不存在！\n");
		PASSWORD::OpenFile_End(File);
		return FALSE;
	}

	PASSWORD::OpenFile_End(File);

	PASSWORD::ClearFileContent();
	File = PASSWORD::OpenFile_Write();

	for (int i = 0; i < m_UserNum; i++)
	{
		Pass_word PW;
		PW.AccoundLenght = strlen(m_DATAINFO[i].Account);
		PW.DataHeadLenght = sizeof(Pass_word);
		PW.PasswordLenght = strlen(m_DATAINFO[i].Password);
		PW.UserInfoLenght = strlen(m_DATAINFO[i].UserInfo);
		fwrite(&PW, PW.DataHeadLenght, 1, File);

		PASSWORD::Encryption(m_DATAINFO[i].Account);
		PASSWORD::WriteEncryptionInfo(File);
		PASSWORD::Encryption(m_DATAINFO[i].Password);
		PASSWORD::WriteEncryptionInfo(File);
		PASSWORD::NULL_Encryption(m_DATAINFO[i].UserInfo);
		PASSWORD::WriteEncryptionInfo(File);
	}

	PASSWORD::OpenFile_End(File);

	PASSWORD::DeleteUserDataInfoList();
	PASSWORD::InitData();
	return TRUE;
}

//遍历文件所有信息
void PASSWORD::ErgodicFileAnyInfo()
{
	FILE *File = PASSWORD::OpenFile_Read();

	if (File)
	{
		Pass_word P_W;
		char EncryptionInfo[256] = { 0 };
		int AccountLen = 0;
		int PasswordLen = 0;
		long Offset = 0;
		char Account[256] = { 0 };
		char Password[256] = { 0 };
		char UserInfo[1024] = { 0 };

		int UserNum = 0;

		while (true)
		{
			ZeroMemory(&P_W, sizeof(Pass_word));
			ZeroMemory(&AccountLen, sizeof(int));
			ZeroMemory(&PasswordLen, sizeof(int));

			fread_s(&P_W, sizeof(Pass_word), sizeof(Pass_word), 1, File);
			//数据头 账号 密码
			if (P_W.DataHeadLenght == 0 || P_W.AccoundLenght == 0)
			{
				rewind(File);
				break;
			}
			//账号长度匹配
			fread_s(&AccountLen, sizeof(int), sizeof(int), 1, File);
			if (AccountLen != P_W.AccoundLenght)
			{
				printf("账号数据有误\n");
				PASSWORD::OpenFile_End(File);
				return;
			}
			//密码长度匹配
			fseek(File, P_W.AccoundLenght, SEEK_CUR);
			fread_s(&PasswordLen, sizeof(int), sizeof(int), 1, File);
			if (PasswordLen != P_W.PasswordLenght)
			{
				printf("密码数据有误\n");
				PASSWORD::OpenFile_End(File);
				return;
			}
			//跳到下一个账号
			fseek(File, P_W.PasswordLenght + (long)(P_W.UserInfoLenght + (long long)sizeof(int)), SEEK_CUR);
			UserNum++;
		}
		m_UserNum = UserNum;

		if (m_UserNum == 0)
		{
			printf("当前没有账号！\n");
			return;
		}

		printf("当前账号数 %d\n", UserNum);

		PASSWORD::DeleteUserDataInfoList();
		m_DATAINFO = new USERINFO[UserNum];

		int i = 0;
		while (true)
		{
			ZeroMemory(&P_W, sizeof(Pass_word));
			ZeroMemory(EncryptionInfo, sizeof(EncryptionInfo));
			ZeroMemory(&AccountLen, sizeof(int));
			ZeroMemory(&PasswordLen, sizeof(int));
			ZeroMemory(&Offset, sizeof(long));
			ZeroMemory(Account, sizeof(Account));
			ZeroMemory(Password, sizeof(Password));
			ZeroMemory(UserInfo, sizeof(UserInfo));

			fread_s(&P_W, sizeof(Pass_word), sizeof(Pass_word), 1, File);
			//数据头 账号
			if (P_W.DataHeadLenght == 0 || P_W.AccoundLenght == 0)
			{
				break;
			}
			//账号长度匹配
			fread_s(&AccountLen, sizeof(int), sizeof(int), 1, File);
			if (AccountLen != P_W.AccoundLenght)
			{
				printf("账号数据有误\n");
				PASSWORD::OpenFile_End(File);
				return;
			}
			//密码长度匹配
			fseek(File, P_W.AccoundLenght, SEEK_CUR);
			fread_s(&PasswordLen, sizeof(int), sizeof(int), 1, File);
			if (PasswordLen != P_W.PasswordLenght)
			{
				printf("密码数据有误\n");
				PASSWORD::OpenFile_End(File);
				return;
			}

			//退到账号信息头的前面读取账号信息和密码信息和用户信息
			Offset = sizeof(int) + P_W.AccoundLenght + sizeof(int);
			fseek(File, -Offset, SEEK_CUR);

			fread_s(EncryptionInfo, sizeof(EncryptionInfo), P_W.AccoundLenght + (long long)sizeof(int), 1, File);
			//解密账号数据
			PASSWORD::Decode(EncryptionInfo, Account);

			fread_s(EncryptionInfo, sizeof(EncryptionInfo), P_W.PasswordLenght + (long long)sizeof(int), 1, File);
			//解密密码信息
			PASSWORD::Decode(EncryptionInfo, Password);

			fread_s(EncryptionInfo, sizeof(EncryptionInfo), (size_t)(P_W.UserInfoLenght + (long long)sizeof(int)), 1, File);
			//解密用户信息
			PASSWORD::Decode(EncryptionInfo, UserInfo);

			memcpy_s(m_DATAINFO[i].Account, sizeof(m_DATAINFO[i].Account), Account, sizeof(Account));
			memcpy_s(m_DATAINFO[i].Password, sizeof(m_DATAINFO[i].Password), Password, sizeof(Password));
			memcpy_s(m_DATAINFO[i].UserInfo, sizeof(m_DATAINFO[i].UserInfo), UserInfo, sizeof(UserInfo));
			i++;
		}

		system("cls");
		for (int j = 0; j < UserNum; j++)
		{
			//printf("Account : %s\nPassword : %s\nUserInfo : %s\n", m_DATAINFO[j].Account, m_DATAINFO[j].Password, m_DATAINFO[j].UserInfo);
			printf("Account : %s\n", m_DATAINFO[j].Account);
		}
	}

	PASSWORD::OpenFile_End(File);
}

//空信息加密
//信息为空,还是存在信息头的四个字节
BOOL PASSWORD::NULL_Encryption(const char *Info)
{
	if (Info == NULL)
	{
		//前四个字节为数据的长
		*((int*)m_EncryptionInfo) = 0;
		return FALSE;
	}
	PASSWORD::Encryption(Info);
	return TRUE;
}

//写入缓存中的数据
void PASSWORD::InsertData(FILE *File)
{
	for (int i = 0; i < m_UserNum; i++)
	{
		Pass_word PW;
		PW.AccoundLenght = strlen(m_DATAINFO[i].Account);
		PW.DataHeadLenght = sizeof(Pass_word);
		PW.PasswordLenght = strlen(m_DATAINFO[i].Password);
		PW.UserInfoLenght = strlen(m_DATAINFO[i].UserInfo);
		fwrite(&PW, PW.DataHeadLenght, 1, File);

		PASSWORD::Encryption(m_DATAINFO[i].Account);
		PASSWORD::WriteEncryptionInfo(File);
		PASSWORD::Encryption(m_DATAINFO[i].Password);
		PASSWORD::WriteEncryptionInfo(File);
		PASSWORD::NULL_Encryption(m_DATAINFO[i].UserInfo);
		PASSWORD::WriteEncryptionInfo(File);
	}
}

void PASSWORD::InsertData()
{
	PASSWORD::ClearFileContent();

	FILE *File = PASSWORD::OpenFile_Write();

	PASSWORD::InsertData(File);

	PASSWORD::OpenFile_End(File);
}

//写入加密数据
void PASSWORD::WriteEncryptionInfo(FILE *File)
{
	//加密数据及信息头
	size_t Fwrite = fwrite(m_EncryptionInfo, sizeof(int) + *((int*)m_EncryptionInfo), 1, File);

	PASSWORD::DeleteMemory();
}

//字符串比较 相同返回TRUE
BOOL PASSWORD::StringCompare(const char *Str_1, const char *Str_2)
{
	PASSWORD::Assert((void*)Str_1);
	PASSWORD::Assert((void*)Str_2);

	int Str_1_Len = strlen(Str_1);
	int Str_2_Len = strlen(Str_2);

	if (Str_1_Len < Str_2_Len)
	{
		Str_1_Len = Str_2_Len;
	}

	int i = 0;
	while (true)
	{
		if (Str_1_Len == i)
		{
			return TRUE;
		}
		if (Str_1[i] != Str_2[i])
		{
			return FALSE;
		}
		i++;
	}
	return TRUE;
}

//清除文件内容
void PASSWORD::ClearFileContent()
{
	PASSWORD::Clear(m_FileName);
}

//追加的方式打开
FILE *PASSWORD::OpenFile_Write()
{
	FILE *File = NULL;
	fopen_s(&File, m_FileName, "ab+");
	if (File)
	{
		return File;
	}
	return NULL;
}
//以二进制模式打开
FILE *PASSWORD::OpenFile_Read()
{
	FILE *File = NULL;
	fopen_s(&File, m_FileName, "rb+");
	if (File)
	{
		return File;
	}
	return NULL;
}

//打开文件结束
void PASSWORD::OpenFile_End(FILE *File)
{
	if (File)
	{
		fclose(File);
		File = NULL;
	}
}

void PASSWORD::Clear(const char *FileName)
{
	PASSWORD::Assert((void*)FileName);

	FILE *File = NULL;
	fopen_s(&File, FileName, "w+");
	if (File)
	{
		PASSWORD::OpenFile_End(File);
	}
}

void PASSWORD::Assert(void *Pointer)
{
	assert(Pointer);
}

void PASSWORD::DeleteMemory()
{
	ZeroMemory(m_EncryptionInfo, sizeof(m_EncryptionInfo));
}







//=================================================

PASSENGINE::PASSENGINE()
{
	PASSENGINE::Get_Password();
}
PASSENGINE::~PASSENGINE()
{
	delete m_PW;
	m_PW = NULL;
}
bool PASSENGINE::EnterPassword()
{
	system("cls");
	std::cout << "输入Password：";
	std::cin >> m_Password;

	if (strcmp(m_Password, _Pass_word) != 0)
	{
		m_ImportPasswordOk = false;
		return false;
	}
	m_ImportPasswordOk = true;
	return true;
}
void PASSENGINE::Get_Password()
{
	FILE *File = NULL;
	fopen_s(&File, FileName, "rb+");
	if (File)
	{
		int PasswordLen = 0;
		fread_s(&PasswordLen,sizeof(PasswordLen),sizeof(int),1,File);
		if (PasswordLen == 0)
		{
			system("cls");
			printf("未进行设置密码,请输入密码进行设置！\n");

			PASSENGINE::Set_Password(File);
		}
		else
		{
			ZeroMemory(_Pass_word, sizeof(_Pass_word));
			ZeroMemory(m_EncryptionInfo, sizeof(m_EncryptionInfo));
			rewind(File);
			fread_s(m_EncryptionInfo, sizeof(m_EncryptionInfo), PasswordLen + sizeof(int), 1, File);

			int TempLen = *((int*)m_EncryptionInfo);
			for (int i = 0; i < TempLen; i++)
			{
				_Pass_word[i] = m_EncryptionInfo[i + sizeof(int)] - 1;
			}
		}
	}

	fclose(File);
	File = NULL;
}
void PASSENGINE::Set_Password(FILE *File)
{
	ZeroMemory(_Pass_word, sizeof(_Pass_word));
	ZeroMemory(m_EncryptionInfo, sizeof(m_EncryptionInfo));
	do
	{
		printf("请输入设置的密码：");
		std::cin >> _Pass_word;
		char Buf[256] = { 0 };
		printf("再次确认的密码：");
		std::cin >> Buf;
		if (strcmp(_Pass_word, Buf) == 0)
		{
			break;
		}
		printf("密码不一致,请重新输入！");
		system("cls");
	} while (true);
	rewind(File);
	//数据的长
	int TempLen = strlen(_Pass_word);
	//前四个字节为数据的长
	*((int*)m_EncryptionInfo) = TempLen;
	for (int i = 0; i < TempLen; i++)
	{
		m_EncryptionInfo[i + sizeof(int)] = _Pass_word[i] + 1;
	}
	fwrite(m_EncryptionInfo, sizeof(int) + *((int*)m_EncryptionInfo), 1, File);
	printf("设置密码成功,请不要忘记了哦！\n");
	Sleep(500);
	system("cls");
}

void PASSENGINE::Run()
{
	PASSENGINE::EnterPassword();
	while (true)
	{
		if (m_ImportPasswordOk)
		{
			if (m_PassOk == false)//只显示一次
			{
				std::cout << "密码正确" << std::endl;
				Sleep(500);
			}
			system("cls");
			PASSENGINE::_Password();
		}
		else
		{
			std::cout << "密码不正确，请重新输入！" << std::endl;
			Sleep(300);
			system("cls");
			PASSENGINE::EnterPassword();
		}
	}
}
void PASSENGINE::_Password()
{
	m_PassOk = true;
	for (int i = 0; i < m_PW->GetUserNum(); i++)
	{
		printf("账号:%s 获取信息按%d输出!\n", m_PW->GetDATAINFO()[i].Account, i + 1);
	}
	PASSENGINE::_Print();
	std::cin >> m_Code;
	PASSENGINE::_SwitchCode(m_Code);
}
void PASSENGINE::_Print()
{

	std::cout << "终结支付密码,Bank密码信息按5000不按文件输出，将直接显示" << std::endl;
	std::cout << "                                          " << std::endl;
	std::cout << "9527(保存一个账号)/9528(删除一个账号)" << std::endl;
	std::cout << "9529(更改一个账号的账号)/9530(更改一个账号的密码)/9531(更改一个账号的信息)" << std::endl;
	std::cout << "88888888(清空数据文件功能有问题！抱歉！)666(刷新数据)" << std::endl;
	std::cout << "                                          " << std::endl;
	std::cout << "5176 / 0(退出)，根据命令进行操作：";
}
void PASSENGINE::_SwitchCode(int Code)
{
	if (Code != 0 && Code != 5000 && Code != 5176 && Code != 88888888 && Code != 666
		&& Code != 9527 && Code != 9528 && Code != 9529 && Code != 9530 && Code != 9531)
	{
		if (Code <= m_PW->GetUserNum())
		{
			system("cls");
			printf("\n");
			printf("------------------------------------------------------------------------------------------\n");
			printf("账号：<%s>   的信息如下!\n密码为：<%s>\n账号的信息为：<%s>\n",
				m_PW->GetDATAINFO()[Code - 1].Account,
				m_PW->GetDATAINFO()[Code - 1].Password,
				m_PW->GetDATAINFO()[Code - 1].UserInfo);
			printf("------------------------------------------------------------------------------------------\n");
			printf("\n");
			system("pause");
			system("cls");
		}
		else
		{
			printf("\n");
			printf("------------------------------------------------------------------------------------------\n");
			printf("并没有这个 ----->>>Code <<<-----  ！\n");
			printf("------------------------------------------------------------------------------------------\n");
			printf("\n");
			system("pause");
			system("cls");
		}
	}
	switch (Code)
	{
	case 0: {exit(0); }; break;
	case 5000: 
	{		
		system("cls");
		printf("    926498    \n    输出成功！");
		Sleep(2000);
	}; break;
	case 5176: {exit(0); }; break;
	case 88888888: {/*m_PW->ClearFileContent(); */}; break;
	case 666: {m_PW->InitData(); }; break;
	case 9527: {PASSENGINE::_SaveAccount(); }; break;
	case 9528: {PASSENGINE::_DeleteAccount(); }; break;
	case 9529: {PASSENGINE::_ChangeAccount(); }; break;
	case 9530: {PASSENGINE::_ChangePassword(); }; break;
	case 9531: {PASSENGINE::_ChangeUserInfo(); }; break;
	}
}
void PASSENGINE::_SaveAccount()
{
	UserInfo UserData;
	printf("输入你的Account：");
	std::cin >> UserData.Account;
	printf("输入你的Password：");
	std::cin >> UserData.Password;
	printf("输入你的AccountInfo：");
	std::cin >> UserData.UserInfo;
	if (m_PW->SaveData(UserData))
	{
		printf("保存成功！\n");
		Sleep(300);
	}
	m_Code = 666;
}
void PASSENGINE::_DeleteAccount()
{
	char Account[256] = { 0 };
	printf("输入你的Account：");
	std::cin >> Account;
	if(m_PW->DeleteData(Account, DELETEACCOUNT))
	{
		printf("删除成功！\n");
		Sleep(300);
	}
}
void PASSENGINE::_ChangeAccount()
{
	char Account[256] = { 0 };
	char Buf[256] = { 0 };
	printf("输入你的Account：");
	std::cin >> Account;
	printf("输入你的Account新账号的名字：");
	std::cin >> Buf;
	if(m_PW->SetDataAccount(Account, Buf))
	{
		printf("更改成功！\n");
		Sleep(300);
	}
}
void PASSENGINE::_ChangePassword()
{
	char Account[256] = { 0 };
	char Password[256] = { 0 };
	printf("输入你的Account：");
	std::cin >> Account;
	printf("输入你的Password：");
	std::cin >> Password;
	if(m_PW->SetDataPassword(Account, Password))
	{
		printf("更改成功！\n");
		Sleep(300);
	}
}
void PASSENGINE::_ChangeUserInfo()
{
	char Account[256] = { 0 };
	char UserInfo[256] = { 0 };
	printf("输入你的Account：");
	std::cin >> Account;
	printf("输入你的UserInfo：");
	std::cin >> UserInfo;
	if(m_PW->SetDataInfo(Account, UserInfo))
	{
		printf("更改成功！\n");
		Sleep(300);
	}
}