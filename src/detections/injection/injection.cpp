#include "injection.hpp"

bool detections::injection::initialize( )
{
    if ( MH_Initialize( ) != MH_OK )
        return false;

    auto ntdll_module = utils::module( "ntdll.dll" );
    const auto function = ntdll_module[ "RtlGetFullPathName_U" ];

    if ( MH_CreateHook( function.as<void*>( ), &injection::function, reinterpret_cast< void** >( &original_fn ) ) != MH_OK )
        return false;

    if ( MH_EnableHook( MH_ALL_HOOKS ) != MH_OK )
        return false;

    return true;
}

__forceinline ULONG __stdcall detections::injection::function( PCWSTR file_name, ULONG size, PWSTR buffer, PWSTR* short_name )
{
    if ( !verify_pe_file_signature( file_name ) )
    {
        utils::report( "dll injection" );
        return 0;
    }

    return original_fn( file_name, size, buffer, short_name );
}

__forceinline bool detections::injection::verify_pe_file_signature( const wchar_t* file_path )
{
    WINTRUST_FILE_INFO file_information = { 0 };
    file_information.cbStruct = sizeof( WINTRUST_FILE_INFO );
    file_information.pcwszFilePath = file_path;
    file_information.hFile = NULL;
    file_information.pgKnownSubject = NULL;

    GUID guid_action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trust_data = { 0 };
    trust_data.cbStruct = sizeof( WINTRUST_DATA );
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_information;

    LONG result = WinVerifyTrust( NULL, &guid_action, &trust_data );

    return result == ERROR_SUCCESS;
}
