#ifndef INDEX_H
#define INDEX_H
#define MAX_INDEX_ENTRIES 1024
#include "pes.h"

typedef struct {
    uint32_t mode;
    ObjectID hash;
    uint64_t mtime_sec;
    uint32_t size;
    char path[512];
} IndexEntry;

typedef struct {
    IndexEntry entries[MAX_INDEX_ENTRIES];
    int count;
} Index;

// function declarations ONLY
int index_load(Index *idx);
int index_save(const Index *idx);
int index_add(Index *idx, const char *path);
void index_status(const Index *idx);

#endif
