#include "integrity.hpp"
#include <iostream>

bool detections::integrity::initialize( )
{
	utils::windows_ldr::enumerate_ldr( [ ]( utils::ldr_data_table_entry* ldr_entry )
	{
			const auto dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( ldr_entry->dll_base );
			const auto nt_header = reinterpret_cast< IMAGE_NT_HEADERS* >( ( std::uintptr_t )ldr_entry->dll_base + dos_header->e_lfanew );

			auto section_header = IMAGE_FIRST_SECTION( nt_header );
			for ( std::uint32_t i = 0; i < nt_header->FileHeader.NumberOfSections; i++ )
			{
				std::string section_name( reinterpret_cast< char* >( section_header->Name ) );

				if ( section_name == ".text" )
				{
					auto name_hash = CRC::Calculate( ldr_entry->base_dll_name.buffer, ldr_entry->base_dll_name.length, CRC::CRC_32() );
					auto section_hash = CRC::Calculate( reinterpret_cast<void*>((std::uintptr_t)ldr_entry->dll_base + section_header->VirtualAddress), section_header->SizeOfRawData, CRC::CRC_32( ) );

					std::printf( "calculated hash for %ws as 0x%x\n", ldr_entry->base_dll_name.buffer, section_hash );

					std::lock_guard lock( integrity_mutex );
					section_hashes.push_back( { name_hash, section_hash } );

					return false;
				}

				section_header++;
			}


		return false;
	} );


	using namespace std::chrono_literals;
	std::thread( [ ]
		{
			while ( 1 )
			{
				detections::integrity::callback( );
				std::this_thread::sleep_for( 5000ms );
			}
		} ).detach( );

	return true;
}

__forceinline void detections::integrity::callback( )
{
	utils::windows_ldr::enumerate_ldr( [ ] ( utils::ldr_data_table_entry* ldr_entry )
		{
			const auto dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( ldr_entry->dll_base );
			const auto nt_header = reinterpret_cast< IMAGE_NT_HEADERS* >( ( std::uintptr_t )ldr_entry->dll_base + dos_header->e_lfanew );

			auto section_header = IMAGE_FIRST_SECTION( nt_header );
			for ( std::uint32_t i = 0; i < nt_header->FileHeader.NumberOfSections; i++ )
			{
				std::string section_name( reinterpret_cast< char* >( section_header->Name ) );

				if ( section_name == ".text" )
				{
					auto name_hash = CRC::Calculate( ldr_entry->base_dll_name.buffer, ldr_entry->base_dll_name.length, CRC::CRC_32( ) );
					auto section_hash = CRC::Calculate( reinterpret_cast< void* >( ( std::uintptr_t )ldr_entry->dll_base + section_header->VirtualAddress ), section_header->SizeOfRawData, CRC::CRC_32( ) );

					std::lock_guard lock( integrity_mutex );
					auto found_section = std::find_if( section_hashes.begin( ), section_hashes.end( ), [ & ] ( auto& section_data )
					{
						return section_data.first == name_hash;
					} );

					if ( found_section != section_hashes.end( ) )
					{
						if ( found_section->second != section_hash )
						{
							utils::report( "modified .text section" );
							std::printf( "[differed .text]: %ws [0x%x|0x%x]\n", ldr_entry->base_dll_name.buffer, found_section->second, section_hash );
							return false;
						}
					}

					return false;
				}

				section_header++;
			}


			return false;
		} );
}

void detections::integrity::update_integrity( )
{
	section_hashes.clear( );

	utils::windows_ldr::enumerate_ldr( [ & ] ( utils::ldr_data_table_entry* ldr_entry )
		{
			const auto dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( ldr_entry->dll_base );
			const auto nt_header = reinterpret_cast< IMAGE_NT_HEADERS* >( ( std::uintptr_t )ldr_entry->dll_base + dos_header->e_lfanew );

			auto section_header = IMAGE_FIRST_SECTION( nt_header );
			for ( std::uint32_t i = 0; i < nt_header->FileHeader.NumberOfSections; i++ )
			{
				std::string section_name( reinterpret_cast< char* >( section_header->Name ) );

				if ( !section_name.compare( ".text" ) )
				{
					auto name_hash = CRC::Calculate( ldr_entry->base_dll_name.buffer, ldr_entry->base_dll_name.length, CRC::CRC_32( ) );
					auto section_hash = CRC::Calculate( reinterpret_cast< void* >( ( std::uintptr_t )ldr_entry->dll_base + section_header->VirtualAddress ), section_header->SizeOfRawData, CRC::CRC_32( ) );

					std::lock_guard lock( integrity_mutex );
					section_hashes.push_back( { name_hash, section_hash } );
					return false;
				}

				section_header++;
			}


			return false;
		} );
}

// this is all test code
bool detections::integrity::load_and_compare( const std::wstring_view& pe_path, const void* data_section )
{
	std::vector<std::uint8_t> dll_bytes{};

	if ( !std::filesystem::exists( pe_path ) )
		return false;

	std::ifstream pe_file( pe_path.data( ), std::ios::binary );

	if ( !pe_file.is_open( ) )
	{
		return false;
	}

	pe_file.unsetf( std::ios::skipws );
	pe_file.seekg( 0, std::ios::end );

	const std::size_t dll_size = pe_file.tellg( );

	pe_file.seekg( 0, std::ios::beg );
	dll_bytes.reserve( dll_size );
	dll_bytes.insert( dll_bytes.begin( ), std::istream_iterator<std::uint8_t>( pe_file ), std::istream_iterator<std::uint8_t>( ) );
	pe_file.close( );

	if ( dll_bytes.empty( ) )
	{
		return false;
	}

	auto dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( dll_bytes.data( ) );
	std::cout << std::hex << dos_header << std::endl;
	auto nt_headers = reinterpret_cast< IMAGE_NT_HEADERS* >( &dll_bytes.data( )[ dos_header->e_lfanew ] );
	std::vector<std::pair<std::uintptr_t, std::uint8_t>> discrepancies { };
	auto image_section = IMAGE_FIRST_SECTION( nt_headers );
	for ( std::uint32_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++ )
	{
		auto section_name = std::string( reinterpret_cast< char* >( image_section->Name ) );

		if ( section_name == ".text" )
		{
			for ( std::uint32_t i = 0; i < image_section->SizeOfRawData; i++ )
			{
				std::uint8_t* orig = reinterpret_cast< std::uint8_t* >( (std::uintptr_t)dll_bytes.data( ) + image_section->VirtualAddress + i );
				std::uint8_t curr = *reinterpret_cast< std::uint8_t* >( std::uintptr_t( data_section ) + i );

				std::printf( "bytes: 0x%x | 0x%x\n", orig, curr );

				if ( *orig != curr )
				{
					discrepancies.push_back( { std::uintptr_t( data_section ) + i, curr } );
					continue;
				}
			}
		}

		image_section++;
	}

	return discrepancies.empty( );
}