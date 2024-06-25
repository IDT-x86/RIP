#pragma once
#include "../../utils/dependencies/crc.hpp"
#include "../../utils/utils.hpp"
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <fstream>
#include <filesystem>

namespace detections::integrity
{
	bool initialize( );
	void callback( );
	void update_integrity( );

	bool load_and_compare( const std::wstring_view& pe_path, const void* compare_section );

	inline std::mutex integrity_mutex;
	inline std::vector<std::pair<std::uint32_t, std::uint32_t>> section_hashes = {}; // both values consist of hashed named and section value 
}