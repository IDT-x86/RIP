#include "veh.hpp"
#include "../integrity/integrity.hpp"

bool detections::veh::initialize( )
{
	return AddVectoredExceptionHandler( 1, veh::handler ) != NULL;
}

__forceinline LONG __stdcall detections::veh::handler( EXCEPTION_POINTERS* exception_info )
{
	if ( exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION )
		return EXCEPTION_CONTINUE_SEARCH;

	if ( exception_info->ExceptionRecord->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION && exception_info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP )
		return EXCEPTION_CONTINUE_SEARCH;

	static std::atomic<std::uintptr_t> last_rip = 0x0;

	if ( exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP )
	{
		const void* function = ( void* )( last_rip.load( ) );
		veh::remove_trap( function );
		veh::add_trap( function );
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	auto is_gadget = [ & ] ( const std::uintptr_t ret ) -> bool
	{
		return *( std::uint16_t* )ret == 0x23FF ||
			*( std::uint16_t* )ret == 0x26FF ||
			*( std::uint16_t* )ret == 0x27FF ||
			*( std::uint16_t* )ret == 0x65FF ||
			*( std::uint16_t* )ret == 0xE3FF ||
			*( std::uint16_t* )ret == 0xFF41;
	};

	auto is_in_legit_module = [ & ] ( const std::uintptr_t address ) -> bool
	{
		bool is_legit = false;
		utils::windows_ldr::enumerate_ldr( [ & ] ( utils::ldr_data_table_entry* ldr_entry )
			{
				const std::uintptr_t base = reinterpret_cast< std::uintptr_t >( ldr_entry->dll_base );
				const std::uintptr_t end = base + ldr_entry->size_of_image;

				if ( address >= base && address <= end )
					is_legit = true;

				return is_legit;
			} );

		return is_legit;
	};

	auto is_whitelisted_ret = [ ] ( EXCEPTION_POINTERS* info )
	{
		auto it = std::find_if( whitelisted_callees.begin( ), whitelisted_callees.end( ), [ & ] ( std::uintptr_t fn )
			{
				return fn == *( std::uintptr_t *)info->ContextRecord->Rsp;
			} );

		return it != whitelisted_callees.end( );
	};

	if ( auto it = std::find_if( trapped_functions.begin( ), trapped_functions.end( ), [ & ] ( auto& fn ) { return fn.first == exception_info->ContextRecord->Rip; } ); it != trapped_functions.end( ) )
	{
		if ( !is_whitelisted_ret( exception_info ) )
		{
			if ( !is_gadget( *reinterpret_cast< std::uintptr_t* >( exception_info->ContextRecord->Rsp ) ) && is_in_legit_module( *reinterpret_cast<std::uintptr_t*>(exception_info->ContextRecord->Rsp ) ) )
			{
				whitelisted_callees.push_back( *reinterpret_cast< std::uintptr_t* >( exception_info->ContextRecord->Rsp ) );
				DWORD old;
				utils::set_protections( ( void* )it->first, 2, PAGE_EXECUTE_READWRITE, &old );
				memcpy( ( void* )it->first, &( it->second ), 2 );
				utils::set_protections( ( void* )it->first, 2, old, &old );

				last_rip = it->first;

				exception_info->ContextRecord->EFlags |= 0x100;

				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else
			{
				utils::report( "VEH (TRAP)" );
				exception_info->ContextRecord->Rip = *reinterpret_cast< std::uintptr_t* >( exception_info->ContextRecord->Rsp );
				exception_info->ContextRecord->EFlags |= 0x100;
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
		else
		{
			//utils::debug( "called from whitelisted module!" );
			DWORD old;
			utils::set_protections( ( void* )it->first, 2, PAGE_EXECUTE_READWRITE, &old );
			memcpy( ( void* )it->first, &( it->second ), 2 );
			utils::set_protections( ( void* )it->first, 2, old, &old );

			last_rip = it->first;

			exception_info->ContextRecord->EFlags |= 0x100;

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}


	return EXCEPTION_CONTINUE_SEARCH;
}

// this could cause a performance overhead, but i'm not really worried in a small time use application
bool detections::veh::add_trap( const void* function )
{
	if ( !function )
		return false;

	if ( auto it = std::find_if( trapped_functions.begin( ), trapped_functions.end( ), [ & ](auto& fn) {
		return fn.first == (std::uintptr_t)function;
		} ); it != trapped_functions.end( ) )
		return false;

	trapped_functions.push_back( { ( std::uintptr_t )function, *reinterpret_cast< const std::uint16_t* >( function ) } );
	
	char trap_instr[ ] = { 0x0F, 0x0B };
	DWORD old;
	utils::set_protections( ( void* )function, sizeof( trap_instr ), PAGE_EXECUTE_READWRITE, &old );
	memcpy( ( void* )function, trap_instr, sizeof( trap_instr ) );
	utils::set_protections( ( void* )function, sizeof( trap_instr ), old, &old );

	detections::integrity::update_integrity( );

	return true;
}

void detections::veh::remove_trap( const void* function )
{
	if ( auto it = std::find_if( trapped_functions.begin( ), trapped_functions.end( ), [ & ] ( auto& fn ) { return fn.first == (std::uintptr_t)function; } ); it != trapped_functions.end( ) )
	{
		DWORD old;
		utils::set_protections( ( void* )function, 2, PAGE_EXECUTE_READWRITE, &old );
		memcpy( ( void* )function, &( it->second ), 2 );
		utils::set_protections( ( void* )function, 2, old, &old );

		trapped_functions.erase( it );
	}

	detections::integrity::update_integrity( );
}
