#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <iostream>     
#include <algorithm> 
#include <string>
#include <cstring>
#include <fstream>
#include <ctime>
#pragma comment(lib, "psapi.lib")

#define NT_SUCCESS(Status)			(((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS				((NTSTATUS)0x00000000L)
#define ACCESS_DENIED				(NTSTATUS)0xC0000022
#define NtCurrentProcess			((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread				((HANDLE)(LONG_PTR)-2)
