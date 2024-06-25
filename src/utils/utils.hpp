#pragma once
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <functional>
#include <string>
#include <memory>
#include "dependencies/crc.hpp"
#include "disassembler/disassembler.hpp"

extern "C" NTSTATUS NTAPI nt_protect_vm( IN HANDLE, IN PVOID*, IN SIZE_T*, IN ULONG, OUT PULONG );
extern "C" NTSTATUS NTAPI nt_query_virtual_memory( IN HANDLE, IN PVOID, IN DWORD, OUT PVOID, IN SIZE_T, OUT PSIZE_T );
namespace utils
{
    typedef enum _MEMORY_INFORMATION_CLASS {
        MemoryBasicInformation
    } MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;

    struct unicode_string
    {
        USHORT length;
        USHORT max_length;
        PWSTR buffer;
    };

    struct ldr_data_table_entry
    {
        _LIST_ENTRY in_load_order_links;
        _LIST_ENTRY in_memory_order_links;
        _LIST_ENTRY in_initialization_order_links;
        void* dll_base;
        void* entry_point;
        ULONG size_of_image;
        unicode_string full_dll_name;
        unicode_string base_dll_name;
        union {
            UCHAR flag_group[ 4 ];
            ULONG flags;
            struct
            {
                ULONG packaged_binary : 1;
                ULONG marked_for_removal : 1;
                ULONG image_dll : 1;
                ULONG load_nofifications_sent : 1;
                ULONG telemetry_entry_processed : 1;
                ULONG process_static_import : 1;
                ULONG in_legacy_lists : 1;
                ULONG in_indexes : 1;
                ULONG shim_dll : 1;
                ULONG in_exception_table : 1;
                ULONG reserved_flags_1 : 2;
                ULONG load_in_progress : 1;
                ULONG load_config_processed : 1;
                ULONG entry_processed : 1;
                ULONG protect_delay_load : 1;
                ULONG reserved_flags_3 : 2;
                ULONG dont_call_for_threads : 1;
                ULONG process_attach_called : 1;
                ULONG process_attach_failed : 1;
                ULONG cor_deferred_validate : 1;
                ULONG cor_image : 1;
                ULONG dont_relocate : 1;
                ULONG cor_il_only : 1;
                ULONG chpe_image : 1;
                ULONG reserved_flags_5 : 2;
                ULONG redirected : 1;
                ULONG reserved_flags_6 : 2;
                ULONG compat_database_processed : 1;
            };
        };
    };

    class windows_ldr
    {
    public:
        __forceinline static PEB* get_peb( )
        {
            return reinterpret_cast< PEB* >( __readgsqword( 0x60 ) );
        }

        __forceinline static PEB_LDR_DATA* get_ldr( )
        {
            return get_peb( )->Ldr;
        }

        __forceinline static void enumerate_ldr( std::function<bool( ldr_data_table_entry* )> callback )
        {
            const auto head = &get_ldr( )->InMemoryOrderModuleList;
            for ( auto current = head->Flink; current != head; current = current->Flink )
            {
                auto ldr_entry = CONTAINING_RECORD( current, ldr_data_table_entry, in_memory_order_links );
                if ( !ldr_entry )
                    continue;

                if ( callback( ldr_entry ) )
                    break;
            }
        }
    };

    class address
    {
    public:
        address( ) : addr( 0 ) { }
        address( void* address ) : addr( reinterpret_cast< uintptr_t >( address ) ) { }
        address( uintptr_t address ) : addr( address ) { }
        address( const address& address ) : addr( address.addr ) { }

        template <typename t = void*>
        t as( ) const
        {
            return ( t )addr;
        }

        template <typename t = void*>
        t& as_ref( ) const
        {
            return ( t& )addr;
        }

        address add( size_t offset ) const
        {
            return address( addr + offset );
        }

        address sub( size_t offset ) const
        {
            return address( addr - offset );
        }

        address resolve_relative( )
        {
            auto offset = *reinterpret_cast< int32_t* >( addr + 3 );
            return static_cast< address >( addr + offset + 7 );
        }

        address resolve_call( )
        {
            auto offset = *reinterpret_cast< int32_t* >( addr + 1 );
            return static_cast< address >( addr + offset + 5 );
        }

        address& operator+=( size_t offset )
        {
            addr += offset;
            return *this;
        }

        address& operator-=( size_t offset )
        {
            addr -= offset;
            return *this;
        }

        address operator+( size_t offset ) const
        {
            return address( addr + offset );
        }

        address operator-( size_t offset ) const
        {
            return address( addr - offset );
        }

        address& operator=( const address& address )
        {
            addr = address.addr;
            return *this;
        }

        address& operator=( uintptr_t address )
        {
            addr = address;
            return *this;
        }
    private:
        uintptr_t addr;
    };

    class module
    {
    public:
        module( const char* module_name )
        {
            windows_ldr::enumerate_ldr( [ & ] ( ldr_data_table_entry* ldr_entry )
                {
                    if ( !module_name )
                    {
                        m_base = ldr_entry->dll_base;
                        m_size = get_nt_headers( )->OptionalHeader.SizeOfImage;
                        return true;
                    }

                    const auto dll_name_wide = std::wstring( ldr_entry->base_dll_name.buffer );
                    if ( dll_name_wide.empty( ) )
                        return false;

                    if ( module_name == std::string( dll_name_wide.begin( ), dll_name_wide.end( ) ) )
                    {
                        m_base = ldr_entry->dll_base;
                        m_size = get_nt_headers( )->OptionalHeader.SizeOfImage;
                        return true;
                    }

                    return false;
                } );

            if ( !m_base.as<std::uintptr_t>( ) || !m_size )
                return;

            dump_exports( );
        }

        IMAGE_DOS_HEADER* get_dos_header( ) const
        {
            return m_base.as< IMAGE_DOS_HEADER* >( );
        }

        IMAGE_NT_HEADERS* get_nt_headers( ) const
        {
            return m_base.add( get_dos_header( )->e_lfanew ).as< IMAGE_NT_HEADERS* >( );
        }

        address get_base( ) const
        {
            return m_base;
        }

        size_t get_size( ) const
        {
            return m_size;
        }

        template <typename t = void*>
        t get_address( std::size_t offset ) const
        {
            return m_base.add( offset ).as< t >( );
        }

        address operator []( const std::string function_name )
        {
            auto pos = m_exported_funcs.find( function_name );
            if ( pos == m_exported_funcs.end( ) )
                return address( );

            return m_base.add( pos->second );
        }

    private:
        void dump_exports( )
        {
            auto nt_headers = get_nt_headers( );
            if ( !nt_headers )
                return;

            auto export_directory = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
            if ( !export_directory.Size )
                return;

            auto export_data = m_base.add( export_directory.VirtualAddress ).as< IMAGE_EXPORT_DIRECTORY* >( );
            if ( !export_data )
                return;

            auto name_table = m_base.add( export_data->AddressOfNames ).as< uint32_t* >( );
            auto ordinal_table = m_base.add( export_data->AddressOfNameOrdinals ).as< uint16_t* >( );
            auto func_table = m_base.add( export_data->AddressOfFunctions ).as< uint32_t* >( );

            for ( size_t i { }; i < export_data->NumberOfNames; i++ )
                m_exported_funcs.insert( { m_base.add( name_table[ i ] ).as< const char* >( ), func_table[ ordinal_table[ i ] ] } );
        }

        std::unordered_map<std::string, uint32_t> m_exported_funcs { };
        address m_base { };
        size_t m_size { };
    };

    inline void report( const char* report_msg )
    {
        std::printf( "[ac-report]: caught cheat through detection -> %s\n", report_msg );
    }

    inline void debug( const char* debug )
    {
        std::printf( "[ac-debug]: %s\n", debug );
    }

    inline bool set_protections( PVOID addr, SIZE_T size, ULONG new_protect, DWORD* old_protect )
    {
        auto status = nt_protect_vm( reinterpret_cast< HANDLE >( -1 ), &addr, &size, new_protect, old_protect );
        return status == 0x0;
    }

    inline bool query_memory( PVOID addr, MEMORY_BASIC_INFORMATION* info )
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        SIZE_T result;
        auto status = nt_query_virtual_memory( reinterpret_cast< HANDLE >( -1 ), addr, MemoryBasicInformation, &mbi, sizeof( MEMORY_BASIC_INFORMATION ), &result );
        
        if ( info )
            *info = mbi;
        
        return status == 0x0;
    }

    inline std::uint32_t find_section_by_function( std::uintptr_t function )
    {
        if ( !function )
            return NULL;

        MEMORY_BASIC_INFORMATION info = { 0 };
        if ( !query_memory( reinterpret_cast< void* >( function ), &info ) )
            return false;

        std::uint32_t ret_hash = 0;

        utils::windows_ldr::enumerate_ldr( [ & ] ( utils::ldr_data_table_entry* ldr_entry )
            {
                const auto dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( ldr_entry->dll_base );
                const auto nt_header = reinterpret_cast< IMAGE_NT_HEADERS* >( ( std::uintptr_t )ldr_entry->dll_base + dos_header->e_lfanew );

                if ( ( std::uintptr_t )ldr_entry->dll_base != ( std::uintptr_t )info.AllocationBase )
                    return false;

                auto section_header = IMAGE_FIRST_SECTION( nt_header );
                for ( std::uint32_t i = 0; i < nt_header->FileHeader.NumberOfSections; i++ )
                {
                    std::string section_name( reinterpret_cast< char* >( section_header->Name ) );

                    if ( section_name == ".text" )
                    {
                        ret_hash = CRC::Calculate( ldr_entry->base_dll_name.buffer, ldr_entry->base_dll_name.length, CRC::CRC_32( ) );
                        return true;
                    }

                    section_header++;
                }

                return false;
            } );

        return ret_hash;
    }

    inline auto get_function_size = [ ] ( zydis::disassembler* disassembler_ctx, std::uintptr_t address )
    {
        std::size_t size = 0;
        while ( true )
        {
            auto result = disassembler_ctx->disassemble_instruction( reinterpret_cast< void* >( address ), 16 );
            auto instruction = std::get<1>( result );
            size += instruction->length;

            if ( instruction->mnemonic == ZYDIS_MNEMONIC_RET )
                break;

            address += instruction->length;
        }

        return size;
    };

    inline bool is_jmp_valid( std::uintptr_t address )
    {
        auto disassembler = std::make_shared<zydis::disassembler>( );
        std::uintptr_t jmp_destination = address;

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

        auto result = disassembler->disassemble_instruction( reinterpret_cast< void* >( jmp_destination ), 16 );
        auto status = std::get<0>( result );
        auto instruction = std::get<1>( result );
        auto operand = std::get<2>( result );
        while ( ZYAN_SUCCESS( status ) && instruction->mnemonic == ZYDIS_MNEMONIC_JMP )
        {
            //std::printf( "[disassembler]: %s\n", disassembler->format_instruction( *instruction, operand, jmp_destination ).c_str( ) );

            // resolves relative jumps
            if ( instruction->opcode == 0xE9 )
            {
                std::int32_t offset = *reinterpret_cast< std::int32_t* >( jmp_destination + 1 );
                jmp_destination = jmp_destination + offset + 5;
            }
            else if ( instruction->opcode == 0xFF )
            {
                std::int32_t offset = *reinterpret_cast< std::int32_t* >( jmp_destination + 2 );
                jmp_destination = *reinterpret_cast< std::uintptr_t* >( jmp_destination + offset + 6 );
            }

            result = disassembler->disassemble_instruction( reinterpret_cast< void* >( jmp_destination ), 16 );
        }

        return is_in_legit_module( jmp_destination );
    }
}