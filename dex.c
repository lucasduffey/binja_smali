#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef uint8_t             u1;
typedef uint16_t            u2;
typedef uint32_t            u4;
typedef uint64_t            u8;
typedef int8_t              s1;
typedef int16_t             s2;
typedef int32_t             s4;
typedef int64_t             s8;

enum { kSHA1DigestLen = 20 };

struct DexStringId {
    u4 stringDataOff;      /* file offset to string_data_item */
};

struct DexClassLookup {
    int     size;                       // total size, including "size"
    int     numEntries;                 // size of table[]; always power of 2
    struct {
        u4      classDescriptorHash;    // class descriptor hash code
        int     classDescriptorOffset;  // in bytes, from start of DEX
        int     classDefOffset;         // in bytes, from start of DEX
    } table[1];
};


// size: 112
struct DexHeader {
    u1  magic[8];           /* includes version number */
    u4  checksum;           /* adler32 checksum */
    u1  signature[kSHA1DigestLen]; /* SHA-1 hash */
    u4  fileSize;           /* length of entire file */
    u4  headerSize;         /* offset to start of next section */
    u4  endianTag;
    u4  linkSize;
    u4  linkOff;
    u4  mapOff;
    u4  stringIdsSize;
    u4  stringIdsOff;
    u4  typeIdsSize;
    u4  typeIdsOff;
    u4  protoIdsSize;
    u4  protoIdsOff;
    u4  fieldIdsSize;
    u4  fieldIdsOff;
    u4  methodIdsSize;
    u4  methodIdsOff;
    u4  classDefsSize;
    u4  classDefsOff;
    u4  dataSize;
    u4  dataOff;
};

// sizeof: 
struct DexOptHeader {
    u1  magic[8];           /* includes version number */

    u4  dexOffset;          /* file offset of DEX header */
    u4  dexLength;
    u4  depsOffset;         /* offset of optimized DEX dependency table */
    u4  depsLength;
    u4  optOffset;          /* file offset of optimized data tables */
    u4  optLength;

    u4  flags;              /* some info flags */
    u4  checksum;           /* adler32 checksum covering deps/opt */

    /* pad for 64-bit alignment if necessary */
};


/*
struct DexFile {
    // directly-mapped "opt" header 
    const DexOptHeader* pOptHeader;

    // pointers to directly-mapped structs and arrays in base DEX 
    const DexHeader*    pHeader;
    const DexStringId*  pStringIds;
    const DexTypeId*    pTypeIds;
    const DexFieldId*   pFieldIds;
    const DexMethodId*  pMethodIds;
    const DexProtoId*   pProtoIds;
    const DexClassDef*  pClassDefs;
    const DexLink*      pLinkData;

    //
     // These are mapped out of the "auxillary" section, and may not be
     //included in the file.
     //
    const DexClassLookup* pClassLookup;
    const void*         pRegisterMapPool;       // RegisterMapClassPool

    // points to start of DEX file data 
    const u1*           baseAddr;

    // track memory overhead for auxillary structures 
    int                 overhead;

    // additional app-specific data structures associated with the DEX 
    //void*               auxData;
};*/


int main(){
	const void*         pRegisterMapPool;

	printf("s: %i\n", sizeof(struct DexHeader)); // sizeof: 112
	printf("sizeof DexOptHeader: %i\n", sizeof(struct DexOptHeader)); // sizeof: 40
	printf("sizeof DexStringId: %i\n", sizeof(struct DexStringId)); // sizeof: 4
	printf("sizeof DexClassLookup: %i\n", sizeof(struct DexClassLookup)); // sizeof: 4
	
	printf("sizeof pRegisterMapPool: %i\n", sizeof(pRegisterMapPool)); // sizeof: 4
}
