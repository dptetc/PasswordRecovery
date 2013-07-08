#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>

#include "utils.h"

/* import type information from pstorec library */
#import "pstorec.dll" no_namespace

/* Link with the Advapi32.lib file */
#pragma comment(lib, "Advapi32.lib")

typedef HRESULT (WINAPI *PStoreCreateInstance_t)(IPStore **, DWORD, DWORD, DWORD);

static void usage(char* exe );
static int get_ie_ver();
static void dump_ie6();
static void dump_ie7();
static void print_guid(GUID g);

unsigned int log_level = LOG_LEVEL_NONE;

int main(int argc, char **argv){
    int version = 0;

    if (argc == 2) {
        if ( !strncmp(argv[1], "-vv", 3)) {
            log_level = LOG_LEVEL_VERY_VERBOSE;
        } else if (!strncmp(argv[1], "-v", 2)) {
            log_level = LOG_LEVEL_VERBOSE;
        }
        else if (!strncmp(argv[1], "-h", 2)) {
            usage(argv[0]);
            exit(0);
        }
    } else if (argc >= 3) {
        printf("Invalid parameters\n");
        exit(1);
    }

    version = get_ie_ver();
    printf("IE version: %d\n", version);

    // HKEY_CURRENT_USER\Software\Microsoft\Protected Storage System Provider
    // SYSTEM permissions
    VERBOSE(printf("Dumping password from Protected Store:\n"););
    dump_ie6();

    // HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\IntelliForms\Storage2
    VERBOSE(printf("Dumping password from Credentials Store:\n"););
    dump_ie7();

    return 0;
}

static void usage(char* exe ) {
    printf( "Unprotect and dump saved IE passwords\n" );
    printf( "%s [-v | -vv | -h]\n-v\tVerbose\n-vv\tVery verbose\n-h\tHelp", exe );
}

static int get_ie_ver(){
    char regKeyName[] = "SOFTWARE\\Microsoft\\Internet Explorer";
    char regValueName[] = "version";

    char val[_MAX_PATH] ="";
    DWORD valSize = _MAX_PATH;
    DWORD valType;

    HKEY rkey = 0;

    /* Open IE registry key*/
    if( RegOpenKeyEx(HKEY_LOCAL_MACHINE, regKeyName, 0, KEY_READ, &rkey) != ERROR_SUCCESS )
    {
        printf("Failed to open key : HKLM\\%s\n", regKeyName );
        return 1;
    }

    /*Read the version value*/
    if( RegQueryValueEx(rkey, regValueName, 0,  &valType, (unsigned char*)&val, &valSize) != ERROR_SUCCESS )
    {
        printf("Failed to read the key %s\n", regValueName);
        RegCloseKey(rkey);
        return 1;
    }
    VVERBOSE(printf("Type: %d, value: %s\n", valType, val););

    RegCloseKey(rkey);

    return atoi(val);
}

static void dump_ie6()
{
    HRESULT rc = 0;

    /* Get PStoreCreateInstance function ptr from DLL */
    PStoreCreateInstance_t PStoreCreateInstance_func;

    HMODULE lib_handle = LoadLibrary("pstorec.dll");
    PStoreCreateInstance_func = (PStoreCreateInstance_t) GetProcAddress(lib_handle, "PStoreCreateInstance");
    if (NULL == PStoreCreateInstance_func){
        HandleError("GetProcAddress");
    }

    /* Get a pointer to the Protected Storage provider */
    IPStore *ps_provider;
    PStoreCreateInstance_func(&ps_provider,
            NULL,   // get base storage provider
            0,      // reserved
            0       // reserved
    );

    /* Get an interface for enumerating registered types from protected db */
    IEnumPStoreTypesPtr enum_types;
    rc = ps_provider->EnumTypes(0,      // PST_KEY_CURRENT_USER
            0,                          // Reserved, must be set to 0
            &enum_types
    );

    if (0 != rc ) {
        printf("IPStore::EnumTypes method failed.\n");
        ExitProcess(1);
    }

    GUID type, sub_type;
    unsigned long num;
    while((rc = enum_types->raw_Next(
            1,          // number of types requested
            &type,      // GUID
            &num        // pointer to number of types fetched
    ))>=0)
    {
        VERBOSE(printf("Fetched %d type(s): ", num); print_guid(type););

        /* Get an interface for enumerating sub-types */
        IEnumPStoreTypesPtr enum_sub_types;
        ps_provider->EnumSubtypes(0,    // PST_KEY_CURRENT_USER
                &type,
                0,                      // reserved, must be set to 0
                &enum_sub_types);


        while((rc = enum_sub_types->raw_Next(1,     // number of sub-types requested
                &sub_type,                          // GUID
                &num                                // pointer to number of types fetched
        )) >=0)
        {
            VERBOSE(printf(" Fetched %d sub-type(s): ", num); print_guid(sub_type););

            /* Get an nterface for enumerating items */
            IEnumPStoreItemsPtr enum_items;
            ps_provider->EnumItems(0,       // PST_KEY_CURRENT_USER
                    &type,                  // type GUID
                    &sub_type,              // sub type GUID
                    0,                      // reserved, must be 0
                    &enum_items
            );

            LPWSTR item;
            while((rc=enum_items->raw_Next(1,   // number of items requested
                    &item,
                    &num
            )) >=0) {
                printf("  Fetched %d item(s): ", num); wprintf(L"%ws\n", item);

                unsigned long item_len = 0;
                unsigned char *item_data = NULL;

                ps_provider->ReadItem(0,    // PST_KEY_CURRENT_USER
                        &type,              // GUID type
                        &sub_type,          // GUID sub-type
                        item,
                        &item_len,          // stored item length
                        &item_data,         // buffer that contains the stored item
                        NULL,               // Pointer to prompt structure
                        0);
                VVERBOSE(printf("Item len: %d\n", item_len););
                dump_bytes(item_data, item_len, 1);

                /* Free read item */
                CoTaskMemFree(item);
            }
        }
    }
}

static void dump_ie7()
{
//http://www.securityfocus.com/archive/1/458115/30/0/threaded
}

/*typedef struct _GUID {
    DWORD Data1;
    WORD  Data2;
    WORD  Data3;
    BYTE  Data4[8];
} GUID;*/
static void print_guid(GUID g){

    printf("%08x-%04hx-%04hx-", g.Data1, g.Data2, g.Data3);
    for(int i = 0; i<8; ++i){
        if(i==2) {
            printf("-");
        }
        printf("%02x", g.Data4[i]);
    }
    printf("\n");
}