#pragma once

class CAntiBreakpoint {
	public:
		CAntiBreakpoint();
		virtual ~CAntiBreakpoint();

		void Anti_HardwareBreakpoint();
		void Anti_EntrypointBreakpoint();

		HANDLE InitAntiThread();
};
extern CAntiBreakpoint* LPAntiBreakpoint;

