#pragma once
#include <Windows.h>
#include <memory>
#include <vector>
#include <atomic>
#include <tuple>
#include "../../utils/utils.hpp"

namespace detections::veh
{
	bool initialize( );
	LONG __stdcall handler( EXCEPTION_POINTERS* exception_info );

	bool add_trap( const void* function );
	void remove_trap( const void* function );

	inline std::vector<std::pair<uintptr_t, std::uint16_t>> trapped_functions = { };
	inline std::vector<std::uintptr_t> whitelisted_callees = { };
}