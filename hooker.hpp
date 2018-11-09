/*
 * MIT License
 *
 * Copyright (c) 2017 Rokas Kupstys
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#pragma once

#include <type_traits>
#include "hooker.h"

namespace hooker
{
    /// Force-cast between incompatible types.
    template<typename T0, typename T1>
    inline T0 force_cast(T1 input)
    {
        union
        {
            T1 input;
            T0 output;
        } u = { input };
        return u.output;
    };

#if _MSC_VER
#pragma warning(push)  
#pragma warning(disable: 4715)
#endif
#if __cplusplus >= 201402L
#   define CPP14(x) x
    /// Universal call function that takes address as a first argument and any amount of arguments. Address will be called with these arguments. Return type is specified as first template argument.
    /// \param address of function to call.
    /// \param ... any amount of arguments with any types.
    /// \returns value of type specified as first template argument, or none if no type is specified.
    template<typename T0 = void, typename T1 = auto, typename... Args>
    T0 call(T1 address, Args... arguments)
    {
        typedef T0(*UniversalCall)(...);
        if (std::is_void<T0>())
            UniversalCall(address)(arguments...);
        else
            return UniversalCall(address)(arguments...);
    }
#else
#   define CPP14(x)
#endif
#if _MSC_VER
#pragma warning(pop)
#endif

    /// Change protection of memory range.
    /// \param p memory address.
    /// \param size of memory at address p.
    /// \param protection a combination of HOOKER_MEM_* flags.
    /// \param original_protection on supported platforms will be set to current memory protection mode. May be null. If not null - always initialize to a best-guess current protection flags value, because on some platforms (like linux) this variable will not be set.
    template<typename T0 CPP14( CPP14(=void*)), typename T1 CPP14(=auto)>
    T0 mem_protect(T1 p, size_t size, size_t protection, size_t* original_protection=nullptr) { return force_cast<T0>(hooker_mem_protect(force_cast<void*>(p), size, protection, original_protection));  }
    /// Get mnemonic size of current platform.
    template<typename T>
    size_t get_mnemonic_size(T address, size_t min_size) { return hooker_get_mnemonic_size(force_cast<void*>(address), min_size); }

    /// Hotpatch a call.
    template<typename T0 CPP14(=void*), typename T1 CPP14(=auto), typename T2 CPP14(=auto)>
    T0 hotpatch(T1 location, T2 new_proc) { return force_cast<T0>(hooker_hotpatch(force_cast<void*>(location), force_cast<void*>(new_proc))); }
    /// Unhotpatch a call.
    template<typename T0 CPP14(=void*), typename T1 CPP14(=auto)>
    T0 unhotpatch(T1 location) { return force_cast<T0>(hooker_unhotpatch(force_cast<void*>(location))); }

    /// Writes a jump or call hook from `address` to `new_proc`.
    /// \param address a pointer where hook should be written
    /// \param new_proc a pointer where hook should point to.
    /// \param flags any of HOOKER_HOOK_* flags. They may not be combined.
    /// \param nops of bytes to nop after hook instruction. Specify -1 to autocalculate.
    /// \returns null on failure or non-null on success.
    template<typename T1, typename T2>
    bool hook(T1 address, T2 new_proc, size_t flags, size_t nops=-1) { return hooker_hook(force_cast<void*>(address), force_cast<void*>(new_proc), flags, nops) != nullptr; }

    /// Redirect call to custom proc.
    /// \param address a start of original call. Warning: It should not contain any relatively-addressed instructions like calls or jumps.
    /// \param new_proc a proc that will be called instead of original one.
    /// \returns pointer, calling which will invoke original proc. It is user's responsibility to call original code when necessary.
    template<typename T0 CPP14(=void*), typename T1 CPP14(=auto), typename T2 CPP14(=auto)>
    T0 redirect(T1 address, T2 new_proc, size_t flags) { return force_cast<T0>(hooker_redirect(force_cast<void*>(address), force_cast<void*>(new_proc), flags)); }

    /// Unhook a hook created by hooker::hook(.., .., HOOKER_HOOK_REDIRECT, ..).
    /// \param address where hook was written to.
    /// \param original result of hooker::hook() call.
    template<typename T1, typename T2>
    void unhook(T1 address, T2 original) { hooker_unhook(force_cast<void*>(address), force_cast<void*>(original)); }

    /// Return address in object's vmt which is pointing to specified method.
    /// \param object is a pointer to a c++ object.
    /// \param method is a pointer to a c++ object method.
    template<typename T1, typename T2>
    size_t* get_vmt_address(T1 object, T2 method) { return force_cast<T0>(hooker_get_vmt_address(force_cast<void*>(object), force_cast<void*>(method))); }

    /// Find a first occourence of memory pattern.
    /// \param start a pointer to beginning of memory range.
    /// \param size a size of memory range. If size is 0 then entire memory space will be searched. If pattern does not exist this will likely result in a crash.
    /// \param pattern a array of bytes to search for.
    /// \param pattern_len a length of pattern array.
    /// \param a wildcard byte in the pattern array.
    template<typename T0 CPP14(=uint8_t*), typename T1 CPP14(=auto)>
    T0 find_pattern(T1 start, size_t size, uint8_t* pattern, size_t pattern_len, uint8_t wildcard) { return force_cast<T0>(hooker_find_pattern(force_cast<void*>(start), size, pattern, pattern_len, wildcard)); }

    /// Fill memory with nops (0x90 opcode).
    /// \param start of the memory address.
    /// \param size of the memory that will be filled.
    template<typename T1>
    void nop(T1 start, size_t size) { hooker_nop(force_cast<void*>(start), size); }
};
