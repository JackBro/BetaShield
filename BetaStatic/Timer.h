#pragma once
#include <chrono>

template <typename T>
class CTimer
{
	private:
		std::chrono::time_point<std::chrono::high_resolution_clock> tStart;
	public:

		CTimer()
		{
			tStart = std::chrono::high_resolution_clock::now();
		}

		__int64 diff()
		{
			return std::chrono::duration_cast<T>(std::chrono::high_resolution_clock::now() - tStart).count();
		}

		void reset()
		{
			tStart = std::chrono::high_resolution_clock::now();
		}
};
