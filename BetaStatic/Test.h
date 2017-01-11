#pragma once
#include "Services.h"

#ifdef TEST_MODE
class CTest {
	protected:
		void InitTestFunctions();
	public:
		void InitTestMode();
};
#endif
