#include "index.h"
#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int index_load(Index *idx) {
    FILE *f = fopen(INDEX_FILE, "r");
    if (!f) {
        idx->count = 0;
        return 0;
    }

    idx->count = 0;
    char hash_hex[65];

    while (idx->count < MAX_INDEX_ENTRIES) {
        IndexEntry *e = &idx->entries[idx->count];

        if (fscanf(f, "%o %64s %lu %u %511s\n",
                   &e->mode, hash_hex, &e->mtime_sec, &e->size, e->path) != 5) {
            break;
        }

        hex_to_hash(hash_hex, &e->hash);
        idx->count++;
    }

    fclose(f);
    return 0;
}

int index_save(const Index *idx) {
    FILE *f = fopen(INDEX_FILE ".tmp", "w");
    if (!f) return -1;

    for (int i = 0; i < idx->count; i++) {
        const IndexEntry *e = &idx->entries[i];

        char hash_hex[65];
        hash_to_hex(&e->hash, hash_hex);

        fprintf(f, "%06o %s %lu %u %s\n",
                e->mode, hash_hex, e->mtime_sec, e->size, e->path);
    }

    fflush(f);
    fsync(fileno(f));
    fclose(f);

    rename(INDEX_FILE ".tmp", INDEX_FILE);
    return 0;
}

int index_add(Index *idx, const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    char *data = malloc(st.st_size ? st.st_size : 1);
    if (!data) {
        fclose(f);
        return -1;
    }

    if (fread(data, 1, st.st_size, f) != (size_t)st.st_size) {
        free(data);
        fclose(f);
        return -1;
    }

    fclose(f);

    ObjectID hash;
    if (object_write(OBJ_BLOB, data, st.st_size, &hash) != 0) {
        free(data);
        return -1;
    }

    free(data);

    for (int i = 0; i < idx->count; i++) {
        if (strcmp(idx->entries[i].path, path) == 0) {
            idx->entries[i].hash = hash;
            idx->entries[i].mtime_sec = st.st_mtime;
            idx->entries[i].size = st.st_size;
            return 0;
        }
    }

    if (idx->count >= MAX_INDEX_ENTRIES) return -1;

    IndexEntry *e = &idx->entries[idx->count++];

    e->mode = 100644;
    e->hash = hash;
    e->mtime_sec = st.st_mtime;
    e->size = st.st_size;
    strcpy(e->path, path);

    return 0;
}

void index_status(const Index *idx) {
    printf("Staged changes:\n");

    if (idx->count == 0) {
        printf("  (nothing to show)\n");
        return;
    }

    for (int i = 0; i < idx->count; i++) {
        printf("  staged:     %s\n", idx->entries[i].path);
    }
}
// Phase 3: index_load
