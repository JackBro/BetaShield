#include "ProjectMain.h"
#include "Main.h"
#include "Test.h"
#include "DynamicWinapi.h"
#include "Functions.h"

#ifdef TEST_MODE
void CTest::InitTestMode()
{
	InitTestFunctions();
	printf("Test Mode Initialization completed!\n");
}
#endif
