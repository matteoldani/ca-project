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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
// Internal headers
#include <tm.h>

#include "uthash.h"
#include "macros.h"


#define MAX_SEGMENTS    1000
#define MAX_WORDS       4000

// Required data structures

/**
 * @brief node of a double linked list representing 
 * the write set of a transaction
 */
struct write_set_node {
    void                    *addr;  // this is the address to be written which is also used to acquire the locks
    void                    *value; // the value to be written 
    UT_hash_handle          hh;      // makes the struc an hashtable
};

/**
 * @brief node of a double linked list representing 
 * the read set of a transaction
 */
struct read_set_node {
    void                    *addr; // this is the address to be read which is also used to acquire the locks
    UT_hash_handle          hh;      // makes the struc an hashtable
};

/**
 * @brief data structure holding all the information of a transaction 
 * as required by TL2
 */
struct transaction {
    struct write_set_node   *ws_map; // hashmap containing the write set
    struct read_set_node    *rs_map; // hashmap containing the read set
    bool                    is_ro;    // flag to set a transacrtion as readonly
    uint64_t                rv;
    uint64_t                wv; 
};

struct word_lock {
    void                 *addr;   // word to be assigned to this lock
    atomic_uint_fast64_t lock;    // this is the value used to check if the word is locked
    atomic_uint_fast64_t version; // this is the version of the word lock
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
    size_t                  align;          // Size of a word in the shared memory region (in bytes)
    size_t                  size;
    atomic_uint_fast64_t    global_lock;    // global version lock updated with a compare and swap
    struct word_lock        memory[MAX_SEGMENTS][MAX_WORDS];    // hashmap that maps the words allocated with thie correspondign lock
                                            // Those locks should be the one called "write locks"
    atomic_uint_fast64_t    allocated_segments;
};


static inline bool cas(atomic_uint_fast64_t *ptr, uint64_t old_value, uint64_t new_value){
    return __sync_bool_compare_and_swap(ptr, old_value, new_value);
}

// HELPER FUNCTIONS FOR THE WORD LOCK
static inline bool acquire_word_lock(struct word_lock *lock){
    return cas(&(lock->lock), 0, 1);
}

static inline bool release_word_lock(struct word_lock *lock){
    return cas(&(lock->lock), 1, 0);
}

static inline void get_word_lock(void *addr, struct region *region, struct word_lock ** wl){
    // find segment
    uint64_t segment_idx = ((uintptr_t)addr) >> 32;
    uint64_t word_lock_idx = (((uintptr_t)addr) & 0x7FFFFFFF)/* / region->align*/;
    *wl = &(region->memory[segment_idx][word_lock_idx]);
}

/**
 * This function is responsible to release all the locks in the write set.
 * It will try to realease all the locks up until "last_word_lock" not included
 * If "last word lock" is set to NULL, it will unlock all the set
 **/
void release_write_set_locks(struct region *region, struct transaction *transaction, struct word_lock * last_word_lock){

    for(struct write_set_node *wsn = transaction->ws_map; wsn!=NULL; wsn=wsn->hh.next){
        struct word_lock *word_lock;
        get_word_lock(wsn->addr, region, &word_lock);

        if(last_word_lock == word_lock){
            return;
        }

        while(!release_word_lock(word_lock));      
    }
}

/**
 * This function is responsible to acquire all the locks in the write set.
 * If the funcion succedes then all the locks are taken. Otherwise it will release
 * the already taken locks and return false
 */
bool acquire_write_set_locks(struct region *region, struct transaction *transaction){
    
    // printf("acquire_write_set_locks: begin\n");
    // fflush(stdout);
    for(struct write_set_node *wsn = transaction->ws_map; wsn!=NULL; wsn=wsn->hh.next){
        struct word_lock *word_lock;
        get_word_lock(wsn->addr, region, &word_lock);

        // try to acquire the lock
        if(!acquire_word_lock(word_lock)){
            release_write_set_locks(region, transaction, word_lock);
            // printf("acquire_write_set_locks: failed\n");
            // fflush(stdout);
            return false;
        }
        // maybe a bounded spin is better (like try locking multiple times before failing)
    }
    // printf("acquire_write_set_locks: done\n");
    // fflush(stdout);
    return true;
}

// END OF HELPER FUNCTIONS FOR TH WORD LOCK

void free_transaction(struct transaction *transaction){
    struct write_set_node *current_w, *tmp_w;
    struct read_set_node *current_r, *tmp_r;

    HASH_ITER(hh, transaction->ws_map, current_w, tmp_w) {
        HASH_DEL(transaction->ws_map, current_w);  /* delete; users advances to next */
        free(current_w->value);
        free(current_w);             /* optional- if you want to free  */
    }

    HASH_ITER(hh, transaction->rs_map, current_r, tmp_r) {
        HASH_DEL(transaction->rs_map, current_r);  /* delete; users advances to next */
        free(current_r);             /* optional- if you want to free  */
    }

    free(transaction);
}


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

    for(int i=0; i<MAX_SEGMENTS; i++){
        for(int j=0; j<MAX_WORDS; j++){
            region->memory[i][j].addr  = (void *)malloc(region->align);
            region->memory[i][j].version = 0;
            region->memory[i][j].lock = 0;
        }
    }

    region->global_lock         = 0;
    region->size                = size;
    region->align               = align;
    region->allocated_segments  = 1;

    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared) {
   
    struct region *region = (struct region *)(shared);

    // for all the allocs I have to clean the segment, the lock and the 
    // alloc node itself
    for(int i=0; i<MAX_SEGMENTS; i++){
        for(int j=0; j<MAX_WORDS; j++){
            
            free(region->memory[i][j].addr);
        }
    }

    // I can free the region 
    free(region);
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t unused(shared)) {

    return (void*)(1ULL<<32);
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) {
    struct region *region = (struct region *)shared;
    return region->size;
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
    transaction->rs_map = NULL;
    transaction->ws_map = NULL;

    // TODO check that this is concurrently correct
    transaction->rv = atomic_load(&(region->global_lock));
    return (tx_t)transaction;
}


/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) {
    // TODO: tm_end(shared_t, tx_t)

    struct region *region = (struct region *)shared;
    struct transaction *transaction = (struct transaction*)tx;

    // If the transaction is read only, at this stage I can return 
    if(transaction->is_ro || transaction->ws_map == NULL){
        free_transaction(transaction);
        return true;
    }

    // acquire all the locks in the write set 
    if(!acquire_write_set_locks(region, transaction)){
        free_transaction(transaction);
        return false;
    }

    // Read and increment the global clock/lock
    transaction->wv = atomic_fetch_add_explicit(&(region->global_lock), 1, memory_order_release) + 1;

    // Special case in which rv + 1 = wv -> I don't have to validate the read set 
    if(transaction->wv != transaction->rv+1){
        // I need to validate the read set
        for(struct read_set_node *rsn = transaction->rs_map; rsn!=NULL; rsn=rsn->hh.next){

            // check if the rv >= of the associated versioned write lock
            struct word_lock *word_lock;
            get_word_lock(rsn->addr, region, &word_lock);

            // check if the address is in the write set. In this case I already have the locks
            // otherwise I have to check if the lock is free

            ///////////////////////////////////////////////////////////////////////
            // struct write_set_node *write_set_node;                            //
            // HASH_FIND_PTR(transaction->ws_map, &(rsn->addr), write_set_node); //
            // if(write_set_node != NULL){continue;}                             //
            ///////////////////////////////////////////////////////////////////////

            // TODO MAYBE EVEN IF I HAVE THE LOCK BECAUSE IT IS IN THE WRITE SET, THIS DOES NOT WORK SINCE MY WRITE HAS BEEN OVERWRITTEN BY ANOTHER TRANSACTION
            // IT IS A THEORY

            if(!acquire_word_lock(word_lock)){
                // TODO I need to release all the locks I've already taken (I guess)
                release_write_set_locks(region, transaction, NULL);
                free_transaction(transaction);
                return false;
            }

            if(transaction->rv < word_lock->version){
                release_write_set_locks(region, transaction, NULL);
                free_transaction(transaction);
                return false;
            }

            if(!release_word_lock(word_lock)){
                release_write_set_locks(region, transaction, NULL);
                free_transaction(transaction);
                return false;
            }

        }

    }

    // I have to commit the changed done in the write set
    for(struct write_set_node *wsn = transaction->ws_map; wsn!=NULL; wsn=wsn->hh.next){

        struct word_lock *word_lock;
        get_word_lock(wsn->addr, region, &word_lock);
        // printf("tm_end: Attempting memcpy from src=%p to dest=%p\n", wsn->value, word_lock->addr);
        // fflush(stdout);
        memcpy(word_lock->addr, wsn->value, region->align);
        // printf("tm_end: memcpy success\n");
        // fflush(stdout);
        word_lock->version = transaction->wv;
        // if(!release_word_lock(word_lock)){
        //     printf("tm_end: end badly\n");
        //     fflush(stdout);
        //     return false;
        // }
        while(!release_word_lock(word_lock)){
            printf("tm_end: end badly\n");
            fflush(stdout);
        }
    }
    // printf("tm_end: just before the shit\n");
    // fflush(stdout);
    // release_write_set_locks(region, transaction, NULL);

    // printf("tm_end: end\n");
    // fflush(stdout);
    free_transaction(transaction);
    return true;

}

bool tm_read_read_only(shared_t shared, tx_t tx, void const* source, size_t size, void* target){

    struct region *region = (struct region *)shared;
    struct transaction *transaction = (struct transaction *)tx;


    // I have to check every word because I need to post validate
    for(uintptr_t i=(uintptr_t)source; i<(uintptr_t)source + size; i=i+region->align){

        // sample the lock associated with the word
        struct word_lock *word_lock;
        void *addr_i = (void*)i;
        get_word_lock(addr_i, region, &word_lock);

        memcpy(target + (i - (uintptr_t)(source)), word_lock->addr, region->align);

        // TODO i might want to do a bounded spinlock
        while (!acquire_word_lock(word_lock));
        uint64_t temp_rv = word_lock->version;
        
        if(transaction->rv < temp_rv){
            // Transaction needs to be aborted 
            while(!release_word_lock(word_lock));
            free_transaction(transaction);
            return false;
        }
        while(!release_word_lock(word_lock));

    }
    return true;

}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared, tx_t tx, void const* source, size_t size, void* target) {

    // printf("tm_read: start\n");
    // fflush(stdout);

    struct region *region = (struct region *)shared;
    struct transaction *transaction = (struct transaction *)tx;

    if(transaction->is_ro){
        return tm_read_read_only(shared, tx, source, size, target);
    }

    // I have to check every word
    for(uintptr_t i=(uintptr_t)source; i<(uintptr_t)source + size; i=i+region->align){

        // sample the lock associated with the word
        struct word_lock *word_lock;
        void *addr_i = (void*)i;
        get_word_lock(addr_i, region, &word_lock);

        
        // Check if the word is in the write set        
        struct write_set_node *write_set_node;
        HASH_FIND_PTR(transaction->ws_map, &addr_i, write_set_node); 
        if(write_set_node != NULL){
            // the word is in the write set, then I should read this value
            memcpy(target + (i - (uintptr_t)(source)), write_set_node->value, region->align);    
            continue;        
        }    

         // I need to create a new read set node if not present in the hashmap
        struct read_set_node *read_set_node;
        HASH_FIND_PTR(transaction->rs_map, &addr_i, read_set_node);
        if(read_set_node == NULL){
            read_set_node = (struct read_set_node *)malloc(sizeof(struct read_set_node));
            read_set_node->addr = (void *)i;
            HASH_ADD_PTR(transaction->rs_map, addr, read_set_node);
        }
    

        

        //if (!acquire_word_lock(word_lock)){return false;}
        uint64_t pre_rv = atomic_load(&(word_lock->version));
        //while(!release_word_lock(word_lock));
       
        // the word is not in the write set, I have to read from the region
        // I am not looking for the correct segment, indeed I'm assuming that the user is not asking
        // to read from a freed memory region
        memcpy(target + (i - (uintptr_t)(source)), word_lock->addr, region->align);
        uint64_t post_rv = atomic_load(&(word_lock->version));

        // Check that the lock is nor taken nor changed
        if(!acquire_word_lock(word_lock)){
            free_transaction(transaction);
            return false;
        }
        
        if(post_rv != pre_rv || pre_rv > transaction->rv){
            while(!release_word_lock(word_lock));
            free_transaction(transaction);
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
bool tm_write(shared_t shared, tx_t tx, void const* source, size_t size, void* target) {

    struct region *region = (struct region *)shared;
    struct transaction *transaction = (struct transaction *)tx;
    size_t align = region->align;

    // check every word 
    for(uintptr_t i=(uintptr_t)target; i<(uintptr_t)target + size; i=i+align){

        // check if the write set for this particular word is already present in the map
        struct write_set_node *write_set_node;
        void * addr_i = (void*)i;
        HASH_FIND_PTR(transaction->ws_map, &addr_i, write_set_node);
        
        if(write_set_node == NULL){
            // I just need to create the write set
            write_set_node = (struct write_set_node*) malloc(sizeof(struct write_set_node));
            write_set_node->addr = addr_i;
            write_set_node->value = (void *)(malloc(sizeof(align)));

            // place the node in the hashmap 
            HASH_ADD_PTR(transaction->ws_map, addr, write_set_node);
        } 

        memcpy(write_set_node->value, source+(i-(uintptr_t)target), align);
    }

    return true;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
alloc_t tm_alloc(shared_t shared, tx_t unused(tx), size_t unused(size), void** target) {

    struct region *region = ((struct region*) shared);
    *target = (void *)((atomic_fetch_add_explicit(&(region->allocated_segments), 1, memory_order_release) + 1)<<32);
    return success_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t unused(shared), tx_t unused(tx), void* unused(target)) {
    // TODO: tm_free(shared_t, tx_t, void*)

    return true;
}
