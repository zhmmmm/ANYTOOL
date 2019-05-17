//**********************************************
//Singleton Texture Manager class
//Written by Ben English
//benjamin.english@oit.edu
//
//For use with OpenGL and the FreeImage library
//**********************************************

#ifndef TextureManager_H
#define TextureManager_H

#include <windows.h>
#include <gl/gl.h>
#include <FreeImage.h>
#include <map>

#define TEXTUREMANAGER TextureManager::Inst()

class TextureManager
{
public:
	//图片管理类的单例创建函数
	static TextureManager* Inst();
	virtual ~TextureManager();//析构

	//load a texture and make it the current texture
	//if texID is already in use, it will be unloaded and replaced with this texture
	bool LoadTexture(
		const char* filename,				//要加载的文件名
		const unsigned int texID,			//自定义的图片ID不是OpenGL创建的，
											//但是是其键值对的键值
											//因为这里使用的是map来存储的
											//这两样数据
		GLenum image_format = GL_RGB,		//传入的图片颜色格式
		GLint internal_format = GL_RGB,		//图片存储格式
		GLint level = 0,					//多级图片等级
		GLint border = 0);					//图片边界尺寸

	//传入自定义图片ID卸载纹理
	//free the memory for a texture
	bool UnloadTexture(const unsigned int texID);

	//自定义的图片ID绑定纹理
	//set the current texture
	bool BindTexture(const unsigned int texID);//自定义的图片ID绑定纹理

	//一次性全部卸载所有的纹理
	//free all texture memory
	void UnloadAllTextures();

protected:
	TextureManager();//构造
	TextureManager(const TextureManager& tm);//拷贝构造
	TextureManager& operator=(const TextureManager& tm);//等号赋值

	static TextureManager* m_inst;//单利对象指针
	std::map<unsigned int, GLuint> m_texID;//存储图像ID的map表
};

#endif