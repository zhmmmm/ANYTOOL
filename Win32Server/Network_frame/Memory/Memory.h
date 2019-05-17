#pragma once
#include <vector>

class MemoryPool
{
	struct NODE
	{
		int use;
		int size;
		void* data;
	};

	std::vector<NODE> m_Nodes;

	MemoryPool(const MemoryPool& that);

	MemoryPool& operator = (const MemoryPool& that);

public:

	MemoryPool();

	~MemoryPool();

	void* Allocate(int size);

	void Free(void* data);
};

