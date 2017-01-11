#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <windowsx.h>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <cstdlib>
#include <sddl.h>
#include <Locale>
#include <Sstream>
#include <cstring>
#include <stdio.h>
using namespace std;



#include "../BetaStatic/AntiCheat_Index.h"
#ifdef _DEBUG
#pragma comment(lib, "../__Output/BetaStatic/Debug/BetaStatic.lib")
#else
#pragma comment(lib, "../__Output/BetaStatic/Release/BetaStatic.lib")
#endif
using namespace BetaNameSpace;
