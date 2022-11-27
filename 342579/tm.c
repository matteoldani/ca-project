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

#define FILTERHASH(a)                   ((UNS(a) >> 2) ^ (UNS(a) >> 5))
#define FILTERBITS(a)                   (1 << (FILTERHASH(a) & 1F))


// Required data structures
struct word_lock {
    void            *addr;   // word to be assigned to this lock
    uint64_t        lock;    // this is the value used to check if the word is locked
    uint64_t        version; // this is the version of the word lock
    UT_hash_handle  hh;      // makes the struc an hashtable
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
    uint64_t                rv;    // read version
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
    uint64_t                alloc_lock;     // this is the value used to check if the word_locks struct is locked
    struct word_lock        *word_locks;    // hashmap that maps the words allocated with thie correspondign lock
                                            // Those locks should be the one called "write locks"

    // TODO it might be worth saving the words which were freed so that I can easily abort a transaction
    // which is running concurrently with a free
};


static inline bool cas(uint64_t *ptr, uint64_t old_value, uint64_t new_value){
    return __sync_bool_compare_and_swap(ptr, old_value, new_value);
}

// HELPER FUNCTIONS FOR THE WORD LOCK
static inline bool acquire_word_lock(struct word_lock *lock){
    return cas(&(lock->lock), 0, 1);
}

static inline bool release_word_lock(struct word_lock *lock){
    return cas(&(lock->lock), 1, 0);
}

/**
 * This function is responsible to release all the locks in the write set.
 * It will try to realease all the locks up until "last_word_lock" not included
 * If "last word lock" is set to NULL, it will unlock all the set
 **/
void release_write_set_locks(struct region *region, struct transaction *transaction, struct word_lock * last_word_lock){

    for(struct write_set_node *wsn = transaction->ws_map; wsn!=NULL; wsn=wsn->hh.next){
        struct word_lock *word_lock;
        HASH_FIND_PTR(region->word_locks, &(wsn->addr), word_lock);

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
    
    for(struct write_set_node *wsn = transaction->ws_map; wsn!=NULL; wsn=wsn->hh.next){
        struct word_lock *word_lock;
        HASH_FIND_PTR(region->word_locks, &(wsn->addr), word_lock);

        // try to acquire the lock
        if(!acquire_word_lock(word_lock)){
            release_write_set_locks(region, transaction, word_lock);
            return false;
        }
        // maybe a bounded spin is better (like try locking multiple times before failing)
    }

    return true;
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
    region->allocs_tail = region->allocs_head;
    region->word_locks = NULL;

    // We allocate the shared memory buffer such that its words are correctly
    // aligned.
    if (posix_memalign(&(region->allocs_head->segment), align, size) != 0) {
        free(region);
        return invalid_shared;
    }

    // Creating the word locks for this memory region
    // use calloc to initialize all the locks
    uintptr_t base_addr = (uintptr_t)region->allocs_head->segment;
    for(int i=0; i< (int)(size / align); i++){
        struct word_lock *lock = (struct word_lock *) calloc(sizeof(struct word_lock), 1);
        lock->addr = (void *)base_addr;
        HASH_ADD_PTR(region->word_locks, addr, lock);
        base_addr += align;
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
    struct word_lock *wl, *temp_wl;
    HASH_ITER(hh, region->word_locks, wl, temp_wl) {
        HASH_DEL(region->word_locks, wl);
        free(wl);            
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

    void *result = region->allocs_head->segment;
    return result;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) {
    struct region *region = (struct region *)shared;
    return region->allocs_head->size;
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
    transaction->rv =  atomic_fetch_add_explicit(&(region->global_lock), 0, memory_order_release);
    transaction->wv = 0;

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
        // TODO probably I need some cleanup of the transaction data struct 
        return true;
    }

    // acquire all the locks in the write set 
    if(!acquire_write_set_locks(region, transaction)){
        // printf("Failed to acquire write set lock\n");
        return false;
    }
    

    // Read and increment the global clock/lock
    transaction->wv = atomic_fetch_add_explicit(&(region->global_lock), 1, memory_order_release) + 1;
    // // printf("Done the atomic fetch and add: %d\n", transaction->wv);

    // Special case in which rv + 1 = wv -> I don't have to validate the read set 
    if(transaction->wv != transaction->rv+1){
        // printf("I have to validate the read set\n");
        // fflush(stdout);
        // I need to validate the read set

        for(struct read_set_node *rsn = transaction->rs_map; rsn!=NULL; rsn=rsn->hh.next){

            // check if the rv >= of the associated versioned write lock
            struct word_lock *word_lock;
            HASH_FIND_PTR(region->word_locks, &(rsn->addr), word_lock);

            // check if the address is in the write set. In this case I already have the locks
            // otherwise I have to check if the lock is free

            // TODO MAYBE EVEN IF I HAVE THE LOCK BECAUSE IT IS IN THE WRITE SET, THIS DOES NOT WORK SINCE MY WRITE HAS BEEN OVERWRITTEN BY ANOTHER TRANSACTION
            // IT IS A THEORY

            if(!acquire_word_lock(word_lock)){
                // TODO I need to release all the locks I've already taken (I guess)
                release_write_set_locks(region, transaction, NULL);
                // // printf("tm_end: ending tm_end\n");
                // // fflush(stdout);
                // printf("Done validating the set - ABORT \n");
                // fflush(stdout);
                return false;
            }

            if(transaction->rv < word_lock->version){
                release_write_set_locks(region, transaction, NULL);
                // // printf("tm_end: ending tm_end\n");
                // // fflush(stdout);
                // printf("Done validating the set - ABORT \n");
                // fflush(stdout);
                return false;
            }

            if(!release_word_lock(word_lock)){
                // printf("Done validating the set - ABORT \n");
                // fflush(stdout);
                return false;
            }


            // struct write_set_node *temp_wsn;
            // HASH_FIND_PTR(transaction->ws_map, &(rsn->addr), temp_wsn);
            // if(temp_wsn==NULL){
            //     // try to acquire the locks
            //     if(!acquire_word_lock(word_lock)){
            //         // TODO I need to release all the locks I've already taken (I guess)
            //         release_write_set_locks(region, transaction, NULL);
            //         // // printf("tm_end: ending tm_end\n");
            //         // // fflush(stdout);
            //         return false;
            //     }

            //     // check the version
            //     uint64_t temp_version = word_lock->version;
            //     while(!release_word_lock(word_lock));
            //     if(transaction->rv < temp_version){
            //         // fail the transaction
            //         release_write_set_locks(region, transaction, NULL);
            //         // // printf("tm_end: ending tm_end\n");
            //         // // fflush(stdout);
            //         return false;

            //     }

            // }else{
            //     // in this case the word is already locked by the fact that it is in the write set
            //     if(transaction->rv < word_lock->version){
            //         release_write_set_locks(region, transaction, NULL);
            //         // // printf("tm_end: ending tm_end\n");
            //         // // fflush(stdout);
            //         return false;
            //     }

            // }
        }

        // printf("Done validating the set\n");
        // fflush(stdout);

    }

    // I have to commit the changed done in the write set
    for(struct write_set_node *wsn = transaction->ws_map; wsn!=NULL; wsn=wsn->hh.next){

        struct word_lock *word_lock;
        HASH_FIND_PTR(region->word_locks, &(wsn->addr), word_lock);
        memcpy(wsn->addr, wsn->value, region->align);
        word_lock->version = transaction->wv;
        if(!release_word_lock(word_lock)){
            return false;
        }
    }
    return true;

}

bool tm_read_read_only(shared_t shared, tx_t tx, void const* source, size_t size, void* target){

    struct region *region = (struct region *)shared;
    struct transaction *transaction = (struct transaction *)tx;

    // I can mem copy since I don't need a pre valdiation
    memcpy(target, source, size);
    // // printf("memcpy excuted\n");

    // I have to check every word because I need to post validate
    for(uintptr_t i=(uintptr_t)source; i<(uintptr_t)source + size; i=i+region->align){

        // sample the lock associated with the word
        struct word_lock *word_lock;
        void *addr_i = (void*)i;
        HASH_FIND_PTR(region->word_locks, &addr_i, word_lock);
        if(word_lock==NULL){
            printf("Word lock is null for addr: %p\n", addr_i);
            fflush(stdout);
        }

        // TODO i might want to do a bounded spinlock
        while (!acquire_word_lock(word_lock));
        uint64_t temp_rv = word_lock->version;
        while(!release_word_lock(word_lock));

        if(transaction->rv < temp_rv){
            // Transaction needs to be aborted 
            return false;
        }

    }

    // // printf("tm_read_read_only: ending the readonly transaction\n");
    // // fflush(stdout);
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
    // TODO: tm_read(shared_t, tx_t, void const*, size_t, void*)

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
        HASH_FIND_PTR(region->word_locks, &addr_i, word_lock);

        // TODO i might want to do a bounded spinlock
        while (!acquire_word_lock(word_lock));
        uint64_t temp_rv = word_lock->version;
        while(!release_word_lock(word_lock));

        // I need to create a new read set node if not present in the hashmap
        struct read_set_node *read_set_node;
        HASH_FIND_PTR(transaction->rs_map, &addr_i, read_set_node);
        if(read_set_node == NULL){
            read_set_node = (struct read_set_node *)malloc(sizeof(struct read_set_node));
            read_set_node->addr = (void *)i;
            HASH_ADD_PTR(transaction->rs_map, addr, read_set_node);
        }
        read_set_node->rv = temp_rv;
        
        // Check if the word is in the write set
        
        struct write_set_node *write_set_node;
        HASH_FIND_PTR(transaction->ws_map, &addr_i, write_set_node); 
        if(write_set_node != NULL){
            // the word is in the write set, then I should read this value
            memcpy(target + (i - (uintptr_t)(source)), write_set_node->value, region->align);    
            continue;        
        }
        

        // the word is not in the write set, I have to read from the region
        // I am not looking for the correct segment, indeed I'm assuming that the user is not asking
        // to read from a freed memory region
        memcpy(target + (i - (uintptr_t)(source)), (void *)i, region->align);
        

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
bool tm_write(shared_t shared, tx_t tx, void const* source, size_t size, void* unused(target)) {

    struct region *region = (struct region *)shared;
    struct transaction *transaction = (struct transaction *)tx;

    // check every word 
    for(uintptr_t i=(uintptr_t)target; i<(uintptr_t)target + size; i=i+region->align){

        // check if the write set for this particular word is already present in the map
    
        struct write_set_node *write_set_node;
        void * addr_i = (void*)i;
        HASH_FIND_PTR(transaction->ws_map, &addr_i, write_set_node);
        
        if(write_set_node == NULL){
            // I just need to create the write set
            write_set_node = (struct write_set_node*) malloc(sizeof(struct write_set_node));
            write_set_node->addr = (void *)i;
            write_set_node->value = (void *)(malloc(sizeof(region->align)));

            // place the node in the hashmap 
            HASH_ADD_PTR(transaction->ws_map, addr, write_set_node);
        } 

        // TODO make sure that this variable is dellocated later on
        // if(write_set_node->value == NULL){
        //     write_set_node->value = (void *)(malloc(sizeof(region->align)));
        //     // // // printf("The address of the value is: %p\n", write_set_node->value);
        //     // // // fflush(stdout);
        // }

        memcpy(write_set_node->value, source+(i-(uintptr_t)target), region->align);
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
alloc_t tm_alloc(shared_t shared, tx_t unused(tx), size_t size, void** target) {

    
    
    struct region *region = ((struct region*) shared);
    size_t align = region->align;

    while(!cas(region->alloc_lock, 0, 1));

    align = align < sizeof(struct segment_node*) ? sizeof(void*) : align;

    // create a new segment
    struct segment_node* sn = (struct segment_node *)malloc(sizeof(struct segment_node));

    // this should create and set the address
    if (unlikely(posix_memalign(&(sn->segment), align, size) != 0)) // Allocation failed
        while(!cas(region->alloc_lock, 1, 0));
        return nomem_alloc;

    // TODO check if this works even when head == tail (it should)
    sn->prev = region->allocs_tail;
    sn->next = NULL;
    sn->size = size;
    region->allocs_tail->next = sn;
    region->allocs_tail = sn;

    // Creating the word locks for this memory region
    
    int n_locks = size / region->align; // TODO this might be the wrong aligment

    uintptr_t base_addr = (uintptr_t)sn->segment;
    for(int i=0; i<n_locks; i++){
        struct word_lock *lock = (struct word_lock *) calloc(sizeof(struct word_lock), 1);
        lock->addr = (void *)base_addr;
        base_addr += region->align;
        HASH_ADD_PTR(region->word_locks, addr, lock);
    }

    // set the target to the allocated value 
    *target = sn->segment;

    while(!cas(region->alloc_lock, 1, 0));
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
