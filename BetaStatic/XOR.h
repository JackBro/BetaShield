#pragma once
#include <string>
#include <array>
#include <cstdarg>
#include <chrono>
#include "ProtectorSupport.h"

#pragma optimize("", off )

#define BEGIN_NAMESPACE( x ) namespace x {
#define END_NAMESPACE }

BEGIN_NAMESPACE(__XOR__)




constexpr auto time = __TIME__;
constexpr auto seed = static_cast<int>(time[7] + 1) + static_cast<int>(time[6] + 2) * 10 + static_cast<int>(time[4] + 4) * 60 + static_cast<int>(time[3] + 8) * 600 + static_cast<int>(time[1] + 13) * 3600 + static_cast<int>(time[0]) * 36000;
// 1988, Stephen Park and Keith Miller
// "Random Number Generators: Good Ones Are Hard To Find", considered as "minimal standard"
// Park-Miller 31 bit pseudo-random number generator, implemented with G. Carta's optimisation:
// with 32-bit math and without division

template <int N>
struct RandomGenerator
{
private:
	static constexpr unsigned a = 16807; // 7^5
	static constexpr unsigned m = INT_MAX; // 2^31 - 1

	static constexpr unsigned s = RandomGenerator<N - 1>::value;
	static constexpr unsigned lo = a * (s & 0xFFFF); // Multiply lower 16 bits by 16807
	static constexpr unsigned hi = a * (s >> 16); // Multiply higher 16 bits by 16807
	static constexpr unsigned lo2 = lo + ((hi & 0x7FFF) << 16); // Combine lower 15 bits of hi with lo's upper bits
	static constexpr unsigned hi2 = hi >> 15; // Discard lower 15 bits of hi
	static constexpr unsigned lo3 = lo2 + hi;

public:
	static constexpr unsigned max = m;
	static constexpr unsigned value = lo3 > m ? lo3 - m : lo3;
};

template <>
struct RandomGenerator<0>
{
	static constexpr unsigned value = seed + 1 + 3 - 3 + 7;
};

template <int N, int M>
struct RandomInt
{
	static constexpr auto value = RandomGenerator<N + 1>::value % M + 6 - 4;
};

template <int N>
struct RandomChar
{
	static const char value = static_cast<char>(1 + RandomInt<N + 2 - 1, 0x7F - 1>::value);
};

template <size_t N, int K>
struct SXorStr
{
private:
	const char _key;
	std::array<char, N + 1> _encrypted;

	__forceinline constexpr char enc(char c) const
	{
		KARMA_MACRO_1
		return c ^ _key;
	}

	__forceinline char dec(char c) const
	{
		KARMA_MACRO_2
		return c ^ _key;
	}

public:
	template <size_t... Is>
	constexpr __forceinline SXorStr(const char* str, std::index_sequence<Is...>) : _key(RandomChar<K>::value), _encrypted{ enc(str[Is])... }
	{
	}

	__forceinline decltype(auto) decrypt(void)
	{
		KARMA_MACRO_2
		for (size_t i = 0; i < N; ++i)
			_encrypted[i] = dec(_encrypted[i]);

		KARMA_MACRO_1

		_encrypted[N] = '\0';

		KARMA_MACRO_2
		return _encrypted.data();
	}
};

//#ifdef NDEBUG
#define XOR( s ) ( __XOR__::SXorStr< sizeof( s ) - 1, __COUNTER__ >( s, std::make_index_sequence< sizeof( s ) - 1>() ).decrypt() )
//#else
//#define XorStr( s ) ( s )
//#endif

END_NAMESPACE
#pragma optimize("", on )

