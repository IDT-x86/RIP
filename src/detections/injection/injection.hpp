#pragma once
#include <Windows.h>
#include <cstdio>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include "../../utils/utils.hpp"

#include "../../utils/dependencies/minhook/minhook.hpp"
#pragma comment(lib, "wintrust.lib")

namespace detections::injection
{
	bool initialize( );

	using prototype_fn = ULONG( __stdcall* )( PCWSTR file_name, ULONG size, PWSTR buffer, PWSTR* short_name );
	inline prototype_fn original_fn = nullptr;

	ULONG __stdcall function( PCWSTR file_name, ULONG size, PWSTR buffer, PWSTR* short_name );
	bool verify_pe_file_signature( const wchar_t* file_path );
}