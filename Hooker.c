#include <assert.h>
#include <string.h>
#include "Hooker.h"
#include "hde/hde32.h"
#include "hde/hde64.h"
#if _WIN32
#   include <windows.h>
#elif __linux__
#   include <sys/param.h>
#   include <sys/mman.h>
#   include <unistd.h>
#include <errno.h>

#else
typedef char unsupported_platform[-1];
#endif
#if _M_AMD64 || _M_X64 || _WIN64 || __x86_64__
#   define HOOKER_X64 1
#endif

void* hooker_alloc(size_t size)
{
#if _WIN32
    return VirtualAlloc(0, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#elif __linux__
    return mmap(0, size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
}

void hooker_free(void* memory)
{
#if _WIN32
    VirtualFree(memory, 0, MEM_RELEASE | MEM_DECOMMIT);
#elif __linux__
    munmap(memory, 0);  // TODO: test
#endif
}

size_t hooker_mem_protect(void* p, size_t size, size_t protection)
{
#if _WIN32
    DWORD old = 0;
    if (protection == 0)
        protection = PAGE_EXECUTE_READWRITE;
    if (VirtualProtect(p, size, (DWORD)protection, &old))
        return old;
    return (size_t)HOOKER_ERROR;
#elif __linux__
    size_t page_size = (size_t) sysconf(_SC_PAGE_SIZE);;
    void* page = (void*) ((size_t)p & ~(page_size - 1));
    int flags = PROT_NONE;
    if (protection & HOOKER_MEM_R)
        flags |= PROT_READ;
    if (protection & HOOKER_MEM_W)
        flags |= PROT_WRITE;
    if (protection & HOOKER_MEM_X)
        flags |= PROT_EXEC;
    return mprotect(page, page_size, flags) == 0 ? 1 : 0;
#endif
}

size_t hooker_get_mnemonic_size_x86(void* address, size_t min_size)
{
    hde32s hd;
    size_t size = 0;
    uint8_t* address_t = (uint8_t*)address;
    while (size < min_size)
        size += hde32_disasm(&address_t[size], &hd);
    return size;
}

size_t hooker_get_mnemonic_size_x64(void* address, size_t min_size)
{
    hde64s hd;
    size_t size = 0;
    uint8_t* address_t = (uint8_t*)address;
    while (size < min_size)
        size += hde64_disasm(&address_t[size], &hd);
    return size;
}

size_t hooker_get_mnemonic_size(void* address, size_t min_size)
{
#if HOOKER_X64
    return hooker_get_mnemonic_size_x64(address, min_size);
#else
    return hooker_get_mnemonic_size_x86(address, min_size);
#endif
}

void* hooker_hotpatch(void* location, void* new_proc)
{
    if (*(uint16_t*)location != 0xFF8B)                                          // Verify if location is hot-patchable.
        return (void*)HOOKER_ERROR;
    hooker_hook((uint8_t*)location - 5, new_proc, HOOKER_HOOK_JMP, 0);
    hooker_mem_protect(location, 2, HOOKER_MEM_RWX);
    *(uint16_t*)location = 0xF9EB;                                              // jump back to hotpatch
    hooker_mem_protect(location, 2, HOOKER_MEM_RX);
    return (uint8_t*)location + 2;
}

void* hooker_unhotpatch(void* location)
{
    if (*(uint16_t*)location != 0xF9EB)                                         // Verify that location was hotpatched.
        return (size_t)HOOKER_ERROR;
    hooker_mem_protect(location, 2, HOOKER_MEM_RWX);
    *(uint16_t*)location = 0xFF8B;                                              // mov edi, edi = nop
    hooker_mem_protect(location, 2, HOOKER_MEM_RX);
    return HOOKER_SUCCESS;
}

void hooker_nop_tail(void* address, size_t len, size_t nops)
{
    if (nops == -1)
        return;

    if (nops == 0)
        nops = hooker_get_mnemonic_size(address, len) - len;

    if (nops > 0)
    {
        uint8_t* location_t = (uint8_t*)address;
        hooker_mem_protect(location_t + len, nops, HOOKER_MEM_RWX);
        memset(location_t + len, 0x90, nops);
        hooker_mem_protect(location_t + len, nops, HOOKER_MEM_RX);
    }
}

void* hooker_hook(void* address, void* new_proc, size_t flags, size_t nops)
{
    if (flags == HOOKER_HOOK_REDIRECT)
    {
#if HOOKER_X64
        uint32_t jmp_len = 14;
        size_t hook_type = HOOKER_HOOK_FAT | HOOKER_HOOK_JMP;
#else
        uint32_t jmp_len = 5;
        size_t hook_type = HOOKER_HOOK_JMP;
#endif
        size_t save_bytes = hooker_get_mnemonic_size(address, jmp_len);

        // Create bridge: [len(original bytes)][original bytes][jmp address+len(original bytes)]
        void* bridge = hooker_alloc(save_bytes + jmp_len + 1);
        *(uint8_t*)bridge = (uint8_t) save_bytes;
        // Write overwritten instructions
        memcpy(bridge + 1, address, save_bytes);
        // Write jump to original function
        hooker_hook(bridge + 1 + save_bytes, address + save_bytes, hook_type, -1);
        // Write jump to the new proc
        hooker_hook(address, new_proc, hook_type, nops);
        // Nop bytes after hook
        hooker_nop_tail(address, jmp_len, nops);
        // Bridge is call to original proc
        return bridge + 1;
    }
    else if (flags & HOOKER_HOOK_FAT)
    {
        uint8_t opcode = 0;
        if (flags & HOOKER_HOOK_CALL)
            opcode = 0x15;
        else if (flags & HOOKER_HOOK_JMP)
            opcode = 0x25;
        else
            return HOOKER_ERROR;

        hooker_nop_tail(address, 14, nops);

        // Fat jump to 64 bit address
        const uint8_t jmp_rsp_0[] = {0xFF, opcode, 0x00, 0x00, 0x00, 0x00 };
        hooker_mem_protect(address, 14, HOOKER_MEM_RWX);
        memcpy(address, jmp_rsp_0, sizeof(jmp_rsp_0));
        *(size_t*)((uint8_t*)address + sizeof(jmp_rsp_0)) = (uint64_t)new_proc;
        hooker_mem_protect(address, 14, HOOKER_MEM_RX);
        return HOOKER_SUCCESS;
    }
    else
    {
        uint8_t opcode = 0;
        if (flags & HOOKER_HOOK_CALL)
            opcode = 0xE8;
        else if (flags & HOOKER_HOOK_JMP)
            opcode = 0xE9;

        if (opcode)
        {
            if ((size_t)(MAX(address, new_proc) - MIN(address, new_proc)) > 0x80000000)
                return (void*)HOOKER_ERROR;

            hooker_nop_tail(address, 5, nops);

            hooker_mem_protect(address, 5, HOOKER_MEM_RWX);
            uint8_t* location_t = (uint8_t*)address;
            *location_t = opcode;
            *(uint32_t*)(++location_t) = (uint32_t)((size_t)new_proc - (size_t)address) - 5;
            hooker_mem_protect(address, 5, HOOKER_MEM_RX);
            return HOOKER_SUCCESS;
        }
    }

    return HOOKER_ERROR;
}

void hooker_unhook(void* address, void* original)
{
    // Possible call with HOOKER_SUCCESS or HOOKER_ERROR parameter.
    if (original < (void*) 2)
        return;

    uint8_t restore_len = *(uint8_t*)(original - 1);
    hooker_mem_protect(address, restore_len, HOOKER_MEM_RWX);
    memcpy(address, original, restore_len);
    hooker_mem_protect(address, restore_len, HOOKER_MEM_RX);
    hooker_free(original - 1);
}
