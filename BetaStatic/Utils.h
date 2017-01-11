#pragma once
#include "ProjectMain.h"
#include "BasePointers.h"

class CUtils {
	public:
		void Close();

		void SetFlagForExit();
		bool IsFlaggedForExit();
};