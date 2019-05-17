#include <iostream>
#include "Network_frame/Servers/Servers.h"
#define Main main



int Main()
{
	
	Server server;
	while (true)
	{
		server.RunServer();
	}
	
	server.CloseServer();


	system("pause");
	return 0;
}