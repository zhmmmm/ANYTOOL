#include "CMyBass.h"
#include <iostream>

#pragma comment(lib,"bass.lib")
CMyBass::~CMyBass(){
	if (!m_MusicList.empty())
	{
		for (MLI it=m_MusicList.begin();it!=m_MusicList.end();++it)
		{
			BASS_StreamFree(it->second);
		}
		m_MusicList.clear();
	}
	if (!m_SoundList.empty())
	{
		for (MLI it=m_SoundList.begin();it!=m_SoundList.end();++it)
		{
			BASS_StreamFree(it->second);
		}
		m_SoundList.clear();
	}
	BASS_Free();
}
CMyBass::CMyBass(){
	m_isInit=false;
}
CMyBass::CMyBass(const CMyBass& that){}
CMyBass& CMyBass::operator = (const CMyBass& that){return *this;}
BOOL CMyBass::Init()
{
	if (!m_isInit)
	{
		if(BASS_Init(-1,44100,0,NULL,0))
		{
			m_isInit=true;
			return TRUE;
		}
	}else
	{
		return TRUE;
	}
	return FALSE;
}
CMyBass* CMyBass::GetInstance()
{
	static CMyBass m_Instance;
	return &m_Instance;
}
int CMyBass::LoadSound(string soundPath,DWORD flags)//加载声音
{
	HSTREAM hs=0;
	MLI _findReturn=m_SoundList.find(soundPath);
	if (_findReturn!=m_SoundList.end())//已经存在
	{
		return _findReturn->second;
	}else//并未加载过，可以添加
	{
		hs=BASS_StreamCreateFile(FALSE,soundPath.c_str(),0,0,flags);//从文件加载音乐

		if (hs==NULL){//加载失败
			return hs;
		}else//加载成功
		{
			m_SoundList.insert(make_pair(soundPath,hs));//加入列表
		}
	}
	return hs;

}
int CMyBass::LoadMusic(string musicPath,DWORD flags)
{
	HSTREAM hs=0;
	MLI _findReturn=m_MusicList.find(musicPath);
	if (_findReturn!=m_MusicList.end())//已经存在
	{
		return _findReturn->second;
	}else//并未加载过，可以添加
	{
		hs=BASS_StreamCreateFile(FALSE,musicPath.c_str(),0,0,flags);//从文件加载音乐

		if (hs==NULL){//加载失败
			return hs;
		}else//加载成功
		{
			m_MusicList.insert(make_pair(musicPath,hs));//加入列表
		}
	}
	return hs;
}
BOOL CMyBass::PlaySound(string sName)//播放音效
{
	MLI _findReturn=m_SoundList.find(sName);
	if (_findReturn!=m_SoundList.end())//存在
	{
		return BASS_ChannelPlay(_findReturn->second,TRUE);
	}
	return FALSE;
}
BOOL CMyBass::PlayMusic(string sName,BOOL restart)//播放音乐
{
	MLI _findReturn=m_MusicList.find(sName);
	if (_findReturn!=m_MusicList.end())//存在
	{
		return BASS_ChannelPlay(_findReturn->second,restart);
	}
	return FALSE;
}

int CMyBass::GetData(string sName,void* buf)
{
	MLI _findReturn=m_MusicList.find(sName);
	if (_findReturn!=m_MusicList.end())//存在
	{
		return BASS_ChannelGetData(_findReturn->second,buf,2147483648);
	}
	return 0;
}