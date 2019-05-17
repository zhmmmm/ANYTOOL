#include <iostream>
#include "Network_frame/Client/Client.h"
#define Main main



int Main()
{
	Client client;
	while (true)
	{
		client.RunClient();
	}
	client.CloseClient();


	system("pause");
	return 0;
}