#include <windows.h>

// Taken from Mimikatz: https : //github.com/gentilkiwi/mimikatz/blob/e10bde5b16b747dc09ca5146f93f2beaf74dd17a/modules/kull_m_cred.h#L39-L73
#pragma pack(push, 4)
typedef struct _CRED_ATTRIBUTE
{
    DWORD flags;
    DWORD wdKeywords;
    wchar_t *keywords;
    DWORD dwValue;
    wchar_t *value;
} CRED_ATTRIBUTE, *PCRED_ATTRIBUTE;

typedef struct _CRED_BLOB
{
    DWORD credFlags;
    DWORD credSize;
    DWORD credUnk0;

    DWORD Type;
    DWORD Flags;
    FILETIME LastWritten;
    DWORD unkFlagsOrSize;
    DWORD persist;
    DWORD attributeCount;
    DWORD unk2;
    DWORD unk3;

    DWORD dwTargetName;
    LPWSTR targetName;

    DWORD dwTargetAlias;
    LPWSTR targetAlias;

    DWORD dwComment;
    LPWSTR comment;

    DWORD dwUnkData;
    LPWSTR unkData;

    DWORD dwUserName;
    LPWSTR userName;

    DWORD credentialBlobSize;
    LPWSTR credentialBlob;

    CRED_ATTRIBUTE attributes;
} CRED_BLOB, *PCRED_BLOB;

typedef struct _CRED_BACKUP
{
    DWORD unk0;
    DWORD file_size;
    DWORD unk1;

    CRED_BLOB blobs;

} CRED_BACKUP, *PCRED_BACKUP;
#pragma pack(pop)
char *CredType[] = {"", "Generic", "Domain Password", "Domain Certificate", "Domain Visible Password", "Maximum"};
char *CredentialPersistence[] = {"", "Session", "Local Machine", "Enterprise"};