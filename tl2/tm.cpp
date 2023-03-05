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
// #define _GNU_SOURCE
// #define _POSIX_C_SOURCE   200809L
// #ifdef __STDC_NO_ATOMICS__
//     #error Current C11 compiler does not support atomic operations
// #endif

// External headers
#include <atomic>
#include <iostream>
#include <map>
#include <string.h>
#include <unordered_set>
#include <vector>
// Internal headers
#include <tm.hpp>
#include "macros.h"


#define MAX_SEGMENTS    200
#define MAX_WORDS       7000

// Required data structures


/**
 * @brief data structure holding all the information of a transaction 
 * as required by TL2
 */
struct transaction {
    std::map<uintptr_t, uint64_t>   ws_map; // hashmap containing the write set
    std::unordered_set<uintptr_t>   rs_map; // hashmap containing the read set
    bool                            is_ro;  // flag to set a transacrtion as readonly
    uint64_t                        rv;     // read version
    uint64_t                        wv;     // write version --> used during the commit phase
};


/**
 * The transaction is declared as a thread local variable, even thought it is not ideal,
 * due to a bug of unordered_set/map. Indeed, as explained here: 
 * https://stackoverflow.com/questions/19556554/floating-point-exception-when-storing-something-into-unordered-map
 * we can get a floating pointer exception when adding nodes into the ws/rs_map. As suggested, declaring it global
 * solves the issues.
 */
static thread_local struct transaction transaction;


struct unpacked_word_lock{
    bool locked;
    uint64_t version;
};

struct word_lock {
    uint64_t                addr;   // word to be assigned to this lock
    std::atomic_uint64_t version;  // this is the version of the word lock
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
    **/
    size_t                  align;          // Size of a word in the shared memory region (in bytes)
    size_t                  size;
    std::atomic_uint64_t    global_lock_array[64];    // global version lock updated with a compare and swap
    std::atomic_uint64_t    global_lock;
    struct word_lock        memory[MAX_SEGMENTS][MAX_WORDS];    // hashmap that maps the words allocated with thie correspondign lock
                                            // Those locks should be the one called "write locks"
    std::atomic_uint64_t    allocated_segments;
};


static inline void sample(struct word_lock *lock, struct unpacked_word_lock *ulock){
    uint64_t current_version = lock->version.load();
    ulock->locked = current_version >> 63;
    ulock->version = current_version & ((1ULL << 63)-1);
}

// HELPER FUNCTIONS FOR THE WORD LOCK
static inline bool acquire_word_lock(struct word_lock *lock, struct unpacked_word_lock *ulock){
    
    uint64_t current_version = lock->version.load();
    ulock->locked = current_version >> 63;
    ulock->version = current_version & ((1ULL << 63)-1);

    if(ulock->locked){return false;}

    uint64_t new_version = current_version | (1ULL << 63);
    return lock->version.compare_exchange_strong(current_version, new_version);
}

static inline bool release_word_lock(struct word_lock *lock, struct unpacked_word_lock *ulock){

    uint64_t current_version = lock->version.load();
    
    ulock->locked = current_version >> 63;
    ulock->version = current_version & ((1ULL << 63)-1);

    uint64_t new_version = current_version & ((1ULL << 63)-1);
    return lock->version.compare_exchange_strong(current_version, new_version);
}

static inline bool realease_word_lock_new_version(struct word_lock *lock, uint64_t new_version){
    
    uint64_t current_version = lock->version.load();
    return lock->version.compare_exchange_strong(current_version,  new_version & ((1ULL << 63)-1));
}

static inline void get_word_lock(uint64_t addr, struct region *region, struct word_lock ** wl){
    // find segment
    uint64_t segment_idx = (addr) >> 32;
    uint64_t word_lock_idx = ((addr) & 0x7FFFFFFF)/region->align;
    *wl = &(region->memory[segment_idx][word_lock_idx]);
}

/**
 * This function is responsible to release all the locks in the write set.
 * It will try to realease all the locks up until "last_word_lock" not included
 * If "last word lock" is set to NULL, it will unlock all the set
 **/
void release_write_set_locks(struct region *region, struct word_lock * last_word_lock){

    for(const auto &wsn: transaction.ws_map){
        struct word_lock *word_lock;
        get_word_lock(wsn.first, region, &word_lock);

        if(last_word_lock == word_lock){
            return;
        }
        struct unpacked_word_lock unpacked_word_lock;
        while(!release_word_lock(word_lock, &unpacked_word_lock));      
    }
}

/**
 * This function is responsible to acquire all the locks in the write set.
 * If the funcion succedes then all the locks are taken. Otherwise it will release
 * the already taken locks and return false
 */
bool acquire_write_set_locks(struct region *region){
    
    for(const auto &wsn: transaction.ws_map){
        struct word_lock *word_lock;
        get_word_lock(wsn.first, region, &word_lock);

        // try to acquire the lock
        struct unpacked_word_lock unpacked_word_lock;
        if(!acquire_word_lock(word_lock, &unpacked_word_lock)){
            release_write_set_locks(region, word_lock);
            return false;
        }
        // maybe a bounded spin is better (like try locking multiple times before failing)
    }
    return true;
}

// END OF HELPER FUNCTIONS FOR TH WORD LOCK

void free_transaction(){
    transaction.ws_map.clear();
    transaction.rs_map.clear();
}


/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size, size_t align) noexcept{

    struct region *region = (struct region *) malloc(sizeof(struct region));
    if (unlikely(!region)) {
        return invalid_shared;
    }

    for(int i=0; i<MAX_SEGMENTS; i++){
        for(int j=0; j<MAX_WORDS; j++){
            region->memory[i][j].addr  = 0;
            region->memory[i][j].version = 0;
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
void tm_destroy(shared_t shared) noexcept{
   
    struct region *region = (struct region *)(shared);
    // I can free the region 
    free(region);
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t unused(shared)) noexcept{

    return (void*)(1ULL<<32);
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) noexcept{
    struct region *region = (struct region *)shared;
    return region->size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared) noexcept{
    struct region *region = (struct region *)shared;
    return region->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t unused(shared), bool is_ro) noexcept{

    struct region *region = (struct region *)shared;

    transaction.is_ro = is_ro;

    transaction.rv = region->global_lock_array[32].load();
    return (tx_t)&transaction;
}

bool validate_read_set(struct region *region){

    for(const auto rsn: transaction.rs_map){

        // check if the rv >= of the associated versioned write lock
        struct word_lock *word_lock;
        struct unpacked_word_lock ulock;

        bool is_in_ws_map = false;
        if(transaction.ws_map.find(rsn) != transaction.ws_map.end()){
            is_in_ws_map = true;
        }

        // printf("Is in map: %d\n", is_in_ws_map);

        get_word_lock(rsn, region, &word_lock);
        sample(word_lock, &ulock);

        if(is_in_ws_map){
            // If the address is already in the write set, then I have already acquied the lock 
            // Thus I don't need to check it
            if(transaction.rv < ulock.version){
                release_write_set_locks(region, NULL);
                free_transaction();

                return false;
            }
        }else{
            if(ulock.locked || transaction.rv < ulock.version){
                release_write_set_locks(region, NULL);
                free_transaction();
                return false;
            }
        }

    }

    return true;
}


/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t unused(tx)) noexcept{

    struct region *region = (struct region *)shared;

    // If the transaction is read only, at this stage I can return 
    if(transaction.is_ro || transaction.ws_map.size() == 0){
        free_transaction();
        return true;
    }

    // acquire all the locks in the write set 
    if(!acquire_write_set_locks(region)){
        free_transaction();
        return false;
    }

    // Read and increment the global clock/lock
    transaction.wv = region->global_lock_array[32].fetch_add(1) + 1;

    // Special case in which rv + 1 = wv -> I don't have to validate the read set 
    if(transaction.wv != transaction.rv+1){
        if(!validate_read_set(region)){
            free_transaction();
            return false;
        }
    }

    // I have to commit the changed done in the write set
    for(const auto wsn : transaction.ws_map){
        struct word_lock *word_lock;
        get_word_lock(wsn.first, region, &word_lock);
        memcpy(&(word_lock->addr), &(wsn.second), 8);
        if(unlikely(!realease_word_lock_new_version(word_lock, transaction.wv))){
            free_transaction();
            return false;
        }
    }
    free_transaction();
    return true;

}


bool inline tm_read_only(shared_t shared, void const* source, size_t size, void* target){
    struct region *region = (struct region *)shared;
    struct unpacked_word_lock ulock_post;
    struct word_lock *word_lock;


    // I have to check every word
    for(uintptr_t i=(uintptr_t)source; i<(uintptr_t)source + size; i=i+8){

        // sample the lock associated with the word
        get_word_lock(i, region, &word_lock);
        

        memcpy((void*)((uintptr_t)target + (i - (uintptr_t)(source))), &(word_lock->addr), 8);
        sample(word_lock, &ulock_post);

        if( (ulock_post.version > transaction.rv)|| ulock_post.locked){
            free_transaction();
            return false;
        }

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
bool tm_read(shared_t shared, tx_t unused(tx), void const* source, size_t size, void* target) noexcept{
    struct region *region = (struct region *)shared;
    struct unpacked_word_lock ulock_pre;
    struct unpacked_word_lock ulock_post;
    struct word_lock *word_lock;
    
    if(transaction.is_ro){
                // I have to check every word
        for(uintptr_t i=(uintptr_t)source; i<(uintptr_t)source + size; i=i+8){

            // sample the lock associated with the word
            get_word_lock(i, region, &word_lock);


            memcpy((void*)((uintptr_t)target + (i - (uintptr_t)(source))), &(word_lock->addr), 8);
            sample(word_lock, &ulock_post);

            if( (ulock_post.version > transaction.rv)|| ulock_post.locked){
                free_transaction();
                return false;
            }

        }

        return true;
    }

    

    // I have to check every word
    for(uintptr_t i=(uintptr_t)source; i<(uintptr_t)source + size; i=i+8){

        // sample the lock associated with the word
        get_word_lock(i, region, &word_lock);
        
        // Check if the word is in the write set        
        auto write_set_node = (transaction.ws_map).find(i); 
        if (write_set_node != (transaction.ws_map).end()){
            // the word is in the write set, then I should read this value
            memcpy((void*)((uintptr_t)target + (i - (uintptr_t)(source))), &(write_set_node->second), 8);
            continue;    
        }  

        transaction.rs_map.emplace(i);    

        sample(word_lock, &ulock_pre);
        memcpy((void*)((uintptr_t)target + (i - (uintptr_t)(source))), &(word_lock->addr), 8);
        sample(word_lock, &ulock_post);

        if((ulock_pre.version != ulock_post.version) || 
           (ulock_post.version > transaction.rv)|| 
           ulock_post.locked){
            free_transaction();
            return false;
        }

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
bool tm_write(shared_t shared, tx_t unused(tx), void const* source, size_t size, void* target) noexcept{

    struct region *region = (struct region *)shared;
    
    size_t align = 8;

    // check every word 
    for(uintptr_t i=(uintptr_t)target; i<(uintptr_t)target + size; i=i+align){
        memcpy(&transaction.ws_map[i], (void*)((uintptr_t)source+(i-(uintptr_t)target)), align);
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
Alloc tm_alloc(shared_t shared, tx_t unused(tx), size_t unused(size), void** target) noexcept{

    struct region *region = ((struct region*) shared);
    *target = (void *)((region->allocated_segments.fetch_add(1) + 1) << 32);
    return Alloc::success;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t unused(shared), tx_t unused(tx), void* unused(target)) noexcept {
    // I don't need to free anything
    return true;
}
