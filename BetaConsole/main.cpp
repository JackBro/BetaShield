#include "main.h"

int main(int argc, char** argv)
{
	char* cIpList[] = { "127.0.0.2" };
	Anti_Common lpAnti;
	lpAnti.InitAntiCheat("456", cIpList, 1, "", 0, nullptr, 999);

	int i = 0;
	while (1) {
		printf("I'm working %d\n", i++);
		Sleep(1000);
	}
	return 0;
}