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
// Internal headers
#include <tm.h>

#include "macros.h"

// Required data structures

enum states {
    ABORTED,
    COMMITTED,
    EXECUTING,
};

struct word_lock {
    uint8_t     lock;   // this is the value used to check if the word is locked
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
    struct word_lock        *word_locks; // list of all the locks required for this region    
};

/**
 * @brief node of a double linked list representing 
 * the write set of a transaction
 */
struct write_set_node {
    void                    *addr; // this is the address to be read which is also used to acquire the locks
    void                    *value; // the value to be written 
    struct write_set_node   *next; // next entry in the write set
    struct write_set_node   *prev; // prev entry in the write set
};

/**
 * @brief node of a double linked list representing 
 * the read set of a transaction
 */
struct read_set_node {
    void                    *addr; // this is the address to be read which is also used to acquire the locks
    struct read_set_node    *next; // next entry in the write set
    struct read_set_node    *prev; // prev entry in the write set
};

/**
 * @brief data structure holding all the information of a transaction 
 * as required by TL2
 */
struct transaction {
    struct write_set_node   *ws_head; // write set head
    struct write_set_node   *ws_tail; // write set tail
    struct read_set_node    *rs_head; // read set head
    struct read_set_node    *rs_tail; // read set tail
    uint64_t                rv;       // read version
    uint64_t                wv;       // write version
    bool                    is_ro;    // flag to set a transacrtion as readonly
    
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
    struct segment_node *allocs_head;   // head of the list of the allocated segment
    struct segment_node *allocs_tail;   // tail of the list of the allocated segment     
    size_t              align;          // Size of a word in the shared memory region (in bytes)
    uint64_t            global_lock;    // global version lock updated with a compare and swap
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

    // We allocate the shared memory buffer such that its words are correctly
    // aligned.
    if (posix_memalign(&(region->allocs_head->segment), align, size) != 0) {
        free(region);
        return invalid_shared;
    }

    // Creating the word locks for this memory region
    int n_locks = size / align;
    // use calloc to initialize all the locks
    region->allocs_head->word_locks = (struct word_lock *) calloc(sizeof(struct word_lock), n_locks);

    memset(region->allocs_head->segment, 0, size);
    region->global_lock         = 0;
    region->allocs_head->size        = size;
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
        free(curr->word_locks);
        free(curr);
    }

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

    transaction->is_ro = is_ro;
    transaction->rs_head = NULL;
    transaction->rs_tail = NULL;
    transaction->ws_head = NULL;
    transaction->ws_tail = NULL; 

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
bool tm_read(shared_t unused(shared), tx_t unused(tx), void const* unused(source), size_t unused(size), void* unused(target)) {
    // TODO: tm_read(shared_t, tx_t, void const*, size_t, void*)
    return false;
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
