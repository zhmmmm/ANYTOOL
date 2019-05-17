#ifndef __CMY_Bass_H__
#define __CMY_Bass_H__
#include <Windows.h>
#include <string>
#include <map>
using std::string;
using std::map;
#include <bass.h>

typedef map<string,HSTREAM> ML;//MusicList
typedef ML::iterator MLI;

#define PLAY_MUSIC_R(_n) CMyBass::GetInstance()->PlayMusic(_n,TRUE);
#define PLAY_MUSIC_F(_n) CMyBass::GetInstance()->PlayMusic(_n,FALSE);
#define PLAY_SOUND(_n) CMyBass::GetInstance()->PlaySound(_n);
#define LOAD_MUSIC(_n) CMyBass::GetInstance()->LoadMusic(_n);
#define LOAD_SOUND(_n) CMyBass::GetInstance()->LoadSound(_n);

#define GOMUSIC CMyBass::GetInstance()

class CMyBass
{
public:
	~CMyBass();
	static CMyBass* GetInstance();
	BOOL Init();
	int LoadMusic(string musicPath,DWORD flags=BASS_SAMPLE_LOOP);//º”‘ÿ“Ù¿÷
	int LoadSound(string soundPath,DWORD flags=BASS_SAMPLE_MONO);//º”‘ÿ“Ù–ß
	BOOL PlaySound(string sName);//≤•∑≈“Ù–ß
	BOOL PlayMusic(string sName,BOOL restart=TRUE);//≤•∑≈“Ù¿÷
	int GetData(string sName,void* buf);
protected:
private:
	CMyBass();
	CMyBass(const CMyBass& that);
	CMyBass& operator = (const CMyBass& that);
	ML m_MusicList;
	ML m_SoundList;
	bool m_isInit;
};
#endif
