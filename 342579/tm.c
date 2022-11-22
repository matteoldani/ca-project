/**
 * @file   tm.c
 * @author [...]
 *
 * @section LICENSE
 *
 * [...]
 *
 * @section DESCRIPTION
 *
 * Implementation of your own transaction manager.
 * You can completely rewrite this file (and create more files) as you wish.
 * Only the interface (i.e. exported symbols and semantic) must be preserved.
**/

// Requested features
#define _GNU_SOURCE
#define _POSIX_C_SOURCE   200809L
#ifdef __STDC_NO_ATOMICS__
    #error Current C11 compiler does not support atomic operations
#endif

// External headers
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
// Internal headers
#include <tm.h>

#include "hashmap.h"
#include "macros.h"

#define FILTERHASH(a)                   ((UNS(a) >> 2) ^ (UNS(a) >> 5))
#define FILTERBITS(a)                   (1 << (FILTERHASH(a) & 0x1F))


// Required data structures

enum states {
    ABORTED,
    COMMITTED,
    EXECUTING,
};

struct word_lock {
    void        *addr;   // word to be assigned to this lock
    uint8_t     lock;    // this is the value used to check if the word is locked
    uint64_t    version; // this is the version of the word lock
};

/**
 * @brief node of a double linked list representing 
 * the allocated segment in a region
 */
struct segment_node {
    struct segment_node     *next;
    struct segment_node     *prev;
    void                    *segment;  // Start of the shared memory region (i.e., of the non-deallocable memory segment)
    size_t                  size;      // Size of the segment  
};

/**
 * @brief node of a double linked list representing 
 * the write set of a transaction
 */
struct write_set_node {
    void                    *addr; // this is the address to be read which is also used to acquire the locks
    void                    *value; // the value to be written 
    uint64_t                rv;    // read version
    uint64_t                wv;    // write version
    struct word_lock        *word_lock_addr; // address to the word lock binded with this address 
};

/**
 * @brief node of a double linked list representing 
 * the read set of a transaction
 */
struct read_set_node {
    void                    *addr; // this is the address to be read which is also used to acquire the locks
    uint64_t                rv;    // read version
};

/**
 * @brief data structure holding all the information of a transaction 
 * as required by TL2
 */
struct transaction {
    struct hashmap          *ws_map; // hashmap containing the write set
    struct hashmap          *rs_map; // hashmap containing the read set
    bool                    is_ro;    // flag to set a transacrtion as readonly
    // uint64_t                bloom_filter; // bloom filert used to check if the addrs is already in the write transaction
    enum states             state;
    uint64_t                rv;
};

/**
 * @brief data structure holding all the information of a shared memory
 * region. This will hold all the allocated segment. It is the target of
 * a transaction.
 */
struct region {
    /** 
     * Shared memory segments dynamically allocated via tm_alloc  within transactions. 
     * The first segment is not deallocable and created with the creation of the region 
    */
    struct segment_node     *allocs_head;   // head of the list of the allocated segment
    struct segment_node     *allocs_tail;   // tail of the list of the allocated segment     
    size_t                  align;          // Size of a word in the shared memory region (in bytes)
    atomic_uint_fast64_t    global_lock;    // global version lock updated with a compare and swap
    struct hashmap          *word_locks;    // hashmap that maps the words allocated with thie correspondign lock


    // TODO it might be worth saving the words which were freed so that I can easily abort a transaction
    // which is running concurrently with a free
};


static inline bool cas(uint64_t *ptr, uint64_t old_value, uint64_t new_value){
    return __sync_bool_compare_and_swap(ptr, old_value, new_value);
}

// HELPER FUNCTIONS FOR THE WORD LOCK
static inline bool acquire_word_lock(struct word_lock *lock){
    return cas(lock->lock, 0, 1);
}

static inline bool release_word_lock(struct word_lock *lock){
    return cas(lock->lock, 1, 0);
}
// END OF HELPER FUNCTIONS FOR TH WORD LOCK


// HELPER FUNCTIONS FOR THE READ/WRITE SET HASHMAP


int write_set_compare(const void *a, const void *b, void unused(*udata)){
    const struct write_set_node *node_a = a;
    const struct write_set_node *node_b = b;

    if(node_a->addr > node_b->addr){return 1;}
    else if(node_a->addr < node_b->addr){return -1;}
    else {return 0;}
}

int read_set_compare(const void *a, const void *b, void unused(*udata)){
    const struct read_set_node *node_a = a;
    const struct read_set_node *node_b = b;

    if(node_a->addr > node_b->addr){return 1;}
    else if(node_a->addr < node_b->addr){return -1;}
    else {return 0;}
}

int word_lock_compare(const void *a, const void *b, void unused(*udata)){
    const struct word_lock *node_a = a;
    const struct word_lock *node_b = b;

    if(node_a->addr > node_b->addr){return 1;}
    else if(node_a->addr < node_b->addr){return -1;}
    else {return 0;}
}


uint64_t write_set_hash(const void *item, uint64_t seed0, uint64_t seed1){
    const struct write_set_node *node = item;
    return hashmap_sip(node->addr, sizeof(node->addr), seed0, seed1);
}

uint64_t read_set_hash(const void *item, uint64_t seed0, uint64_t seed1){
    const struct read_set_node *node = item;
    return hashmap_sip(node->addr, sizeof(node->addr), seed0, seed1);
}

uint64_t word_lock_hash(const void *item, uint64_t seed0, uint64_t seed1){
    const struct word_lock *node = item;
    return hashmap_sip(node->addr, sizeof(node->addr), seed0, seed1);
}

// END OF HELPER FUNCTIONS FOR THE READ/WRITE SET HASHMAP


/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size, size_t align) {
    struct region *region = (struct region *) malloc(sizeof(struct region));
    if (unlikely(!region)) {
        return invalid_shared;
    }

    region->allocs_head = (struct segment_node *) malloc(sizeof(struct segment_node));
    if(unlikely(!region->allocs_head)){
        return invalid_shared;
    }

    region->allocs_head->next = NULL;
    region->allocs_head->prev = NULL;
    // TODO maybe is more helpful if this is set to null
    region->allocs_tail = region->allocs_head;

    region->word_locks = hashmap_new(sizeof(struct word_lock), 0, 15, 460399, 
                                            word_lock_hash, word_lock_compare, NULL, NULL);

    // We allocate the shared memory buffer such that its words are correctly
    // aligned.
    if (posix_memalign(&(region->allocs_head->segment), align, size) != 0) {
        free(region);
        return invalid_shared;
    }

    // Creating the word locks for this memory region
    // use calloc to initialize all the locks
    int n_locks = size / align;
    uintptr_t base_addr = region->allocs_head->segment;
    for(int i=0; i<n_locks; i++){
        struct word_lock *lock = (struct word_lock *) calloc(sizeof(struct word_lock), 1);
        lock->addr = base_addr;
        base_addr += region->align;
        hashmap_set(region->word_locks, lock);
    }

    memset(region->allocs_head->segment, 0, size);
    region->global_lock         = 0;
    region->allocs_head->size   = size;
    region->align               = align;

    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared) {
    struct region *region = (struct region *)(shared);

    // for all the allocs I have to clean the segment, the lock and the 
    // alloc node itself
    while(region->allocs_head != NULL){
        struct segment_node * curr = region->allocs_head;
        region->allocs_head = region->allocs_head->next;
        free(curr->segment);
        free(curr);
    }

    // free the map
    hashmap_free(region->word_locks);

    // I can free the region 
    free(region);
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared) {
    struct region *region = (struct region *)shared;
    return region->allocs_head->segment;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) {
    struct region *region = (struct region *)shared;
    return region->allocs_head->size;
    return 0;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared) {
    struct region *region = (struct region *)shared;
    return region->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t unused(shared), bool is_ro) {

    struct transaction *transaction = (struct transaction *)malloc(sizeof(struct transaction));
    struct region *region = (struct region *)shared;

    transaction->is_ro = is_ro;
    transaction->rs_map = hashmap_new(sizeof(struct read_set_node), 0, 15, 460399,
                                            read_set_hash, read_set_compare, NULL, NULL);
    transaction->ws_map = hashmap_new(sizeof(struct write_set_node), 0, 15, 460399, 
                                            write_set_hash, write_set_compare, NULL, NULL);
    // transaction->bloom_filter = 0;
    transaction->state = EXECUTING;

    // TODO check that this is concurrently correct
    transaction->rv = region->global_lock;

    return transaction;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t unused(shared), tx_t unused(tx)) {
    // TODO: tm_end(shared_t, tx_t)
    
    return false;
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared, tx_t unused(tx), void const* unused(source), size_t unused(size), void* unused(target)) {
    // TODO: tm_read(shared_t, tx_t, void const*, size_t, void*)

    struct region *region = (struct region *)shared;
    struct transaction *transaction = (struct transaction *)tx;

    // I have to check every word
    for(uintptr_t i=(uintptr_t)source; i<(uintptr_t)source + size; i=i+region->align){

        // sample the lock associated with the word
        struct word_lock *word_lock = hashmap_get(region->word_locks, &(struct word_lock){.addr=i});

        // TODO i might want to do a bounded spinlock
        while (!acquire_word_lock(word_lock));
        uint64_t temp_rv = word_lock->version;
        while(!release_word_lock(word_lock));

        // I need to create a new read set node if not present in the hashmap
        struct read_set_node *read_set_node = hashmap_get(transaction->rs_map, &(struct read_set_node){.addr = i});
        if(read_set_node == NULL){
            read_set_node = (struct read_set_node *)malloc(sizeof(struct read_set_node));
            read_set_node->addr = i;
        }
        read_set_node->rv = temp_rv;
        
        // Check if the word is in the write set
        struct write_set_node *write_set_node = hashmap_get(transaction->ws_map, &(struct write_set_node){.addr = i});
        if(write_set_node != NULL){
            // the word is in the write set, then I should read this value
            memcpy(target + (i - (uintptr_t)(source)), write_set_node->value, region->align);            
        }else{
            // the word is not in the write set, I have to read from the region
            // I am not looking for the correct segment, indeed I'm assuming that the user is not asking
            // to read from a freed memory region
            memcpy(target + (i - (uintptr_t)(source)), i, region->align);
        }

        // Check that the lock is nor taken nor changed
        if(!acquire_word_lock(word_lock)){
            // I have to abort the transaction
            // TODO check if a simple return false can work
            return false;
        }
        if(word_lock->version > temp_rv){
            while(!release_word_lock(word_lock));
            // I have to abort the transaction
            // TODO check if a simple return false can work
            return false;
        }

        while(!release_word_lock(word_lock));
    }

    return true;
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t unused(shared), tx_t unused(tx), void const* unused(source), size_t unused(size), void* unused(target)) {
    // TODO: tm_write(shared_t, tx_t, void const*, size_t, void*)
    return false;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
alloc_t tm_alloc(shared_t unused(shared), tx_t unused(tx), size_t unused(size), void** unused(target)) {
    // TODO: tm_alloc(shared_t, tx_t, size_t, void**)
    return abort_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t unused(shared), tx_t unused(tx), void* unused(target)) {
    // TODO: tm_free(shared_t, tx_t, void*)
    return false;
}
