#pragma once


#include <stdint.h>
#include <stddef.h>


#define HOOKER_ERROR            (0)
#define HOOKER_SUCCESS          ((void*)1)
#define HOOKER_MEM_R            (1)
#define HOOKER_MEM_W            (2)
#define HOOKER_MEM_X            (4)
#define HOOKER_MEM_RW           (HOOKER_MEM_R|HOOKER_MEM_W)
#define HOOKER_MEM_RX           (HOOKER_MEM_R|HOOKER_MEM_X)
#define HOOKER_MEM_RWX          (HOOKER_MEM_R|HOOKER_MEM_W|HOOKER_MEM_X)

#define HOOKER_HOOK_REDIRECT    (0)
#define HOOKER_HOOK_CALL        (1)
#define HOOKER_HOOK_JMP         (2)
#define HOOKER_HOOK_FAT         (4)

#if __cplusplus
extern "C" {
#endif

/// Change protection of memory range.
size_t hooker_mem_protect(void* p, size_t size, size_t protection);
/// Get x86 mnemonic size of code.
size_t hooker_get_mnemonic_size_x86(void* address, size_t min_size);
/// Get x64 mnemonic size of code.
size_t hooker_get_mnemonic_size_x64(void* address, size_t min_size);
/// Get mnemonic size of current platform.
size_t hooker_get_mnemonic_size(void* address, size_t min_size);

/// Hotpatch a call.
void* hooker_hotpatch(void* location, void* new_proc);
/// Unhotpatch a call.
void* hooker_unhotpatch(void* location);

/// Writes a hook from `address to `new_proc`.
/// \param address a pointer where hook should be written
/// \param new_proc a pointer where hook should point to.
/// \param flags any of HOOKER_HOOK_* flags. They may not be combined.
/// \param number of bytes to nop after hook instruction.
/// \returns null on failure or result depending on flags.
void* hooker_hook(void* address, void* new_proc, size_t flags, size_t nops);
/// Unhook a hook created by hooker_hook(.., .., HOOKER_HOOK_REDIRECT, ..).
/// \param address where hook was written to.
/// \param original result of hooker_hook() call.
void hooker_unhook(void* address, void* original);

#if __cplusplus
};
#endif
