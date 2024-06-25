#include <iostream>
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include "detections/veh/veh.hpp"
#include "detections/integrity/integrity.hpp"
#include "invoker/invoker.hpp"
#include "detections/injection/injection.hpp"

__declspec(dllexport) int test( int a, int b )
{
	std::cout << "called test from legit module!\n";
	return a + b;
}

int main( )
{
	SetConsoleTitleA( "Test Anti-Cheat" );

	if ( !detections::injection::initialize( ) )
	{
		MessageBoxA( NULL, "Failed to initialize AC measures", "Error 1", MB_OK | MB_ICONERROR );
		return 1;
	}

	const auto suspend_thread = utils::module( "KERNELBASE.dll" )[ "SuspendThread" ];
	
	if ( !detections::veh::initialize( ) )
	{
		MessageBoxA( NULL, "Failed to initialize AC measures", "Error 2", MB_OK | MB_ICONERROR );
		return 1;
	}

	if ( !detections::integrity::initialize( ) )
	{
		MessageBoxA( NULL, "Failed to initialize AC measures", "Error 3", MB_OK | MB_ICONERROR );
		return 1;
	}

	detections::veh::add_trap( test );
	detections::veh::add_trap( GetProcAddress );
	detections::veh::add_trap( LoadLibraryA );
	detections::veh::add_trap( MessageBoxA );

	if ( !utils::is_jmp_valid( suspend_thread.as<std::uintptr_t>() ) )
	{
		utils::report( "INVALID JMP" );
	}

	return std::getchar( );
}