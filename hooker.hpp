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
#include <stdexcept>
#include "hooker.h"

namespace hooker
{
    /// Pattern for find_pattern() function.
    template <size_t N>
    struct pattern
    {
        /// Bytes to find. Value of wildcard byte or byte half can be anything.
        uint8_t pattern[N];
        /// Wildcard pattern. Byte value may be one of: 0? = 1, ?0 = 2, ?? = 3.
        uint8_t wildcard[N];
    };

#if __cplusplus >= 201402L
#   define CPP14(x) x
    /// Universal call function that takes address as a first argument and any amount of arguments. Address will be called with these arguments. Return type is specified as first template argument.
    /// \param address of function to call.
    /// \param ... any amount of arguments with any types.
    /// \returns value of type specified as first template argument, or none if no type is specified.
    template<typename Result, typename Addr, typename... Args, typename std::enable_if<std::is_void<Result>::value>::type* = nullptr>
    Result call(Addr address, Args... arguments)
    {
        typedef Result(*UniversalCall)(...);
        reinterpret_cast<UniversalCall>(address)(arguments...);
    }

    /// Universal call function that takes address as a first argument and any amount of arguments. Address will be called with these arguments. Return type is specified as first template argument.
    /// \param address of function to call.
    /// \param ... any amount of arguments with any types.
    /// \returns value of type specified as first template argument, or none if no type is specified.
    template<typename Result, typename Addr, typename... Args, typename std::enable_if<!std::is_void<Result>::value>::type* = nullptr>
    Result call(Addr address, Args... arguments)
    {
        typedef Result(*UniversalCall)(...);
        return UniversalCall(address)(arguments...);
    }

    namespace detail
    {
        // Convert hex character to a number.
        constexpr uint8_t char_to_byte(char c)
        {
            if (c >= '0' && c <= '9')
                return c - '0';
            else if (c >= 'a' && c <= 'f')
                return 0x0A + c - 'a';
            else if (c >= 'A' && c <= 'F')
                return 0x0A + c - 'A';
            else if (c == '?')
                return 0;
            else
                throw std::runtime_error("Not a hex character.");
        }

        // Convert text hex byte at `idx` to binary.
        template <size_t N>
        constexpr uint8_t get_pattern_byte(const char(&s)[N], size_t idx)
        {
            if (s[idx * 3 + 2] != ' ' && s[idx * 3 + 2] != '\0')
                throw std::runtime_error("Improperly formatted pattern.");
            else
                return (char_to_byte(s[idx * 3]) << 4) | char_to_byte(s[idx * 3 + 1]);
        }

        // Convert text wildcard to binary mask.
        template <size_t N>
        constexpr uint8_t get_wildcard_byte(const char(&s)[N], size_t idx)
        {
            return (s[idx * 3] == '?' ? 2 : 0) | (s[idx * 3 + 1] == '?' ? 1 : 0);
        }

        // Convert a character array to binary version and wildcard array.
        template <size_t N, size_t... Is>
        constexpr pattern<sizeof...(Is)> decode_string_pattern(const char(&s)[N], std::index_sequence<Is...>)
        {
            return {
                { get_pattern_byte(s, Is)... },
                { get_wildcard_byte(s, Is)... },
            };
        }
    }

    // Create a binary pattern from raw string litteral in format: "AB C? ?D ??".
    template <size_t N>
    constexpr const pattern<N / 3> mkpat(const char(&s)[N])
    {
        if ((N % 3) == 0)
            return detail::decode_string_pattern(s, std::make_index_sequence<N / 3>());
        else
            throw std::runtime_error("Improperly formatted pattern.");
    }

#else
#   define CPP14(x)
#endif

    /// Change protection of memory range.
    /// \param p memory address.
    /// \param size of memory at address p.
    /// \param protection a combination of HOOKER_MEM_* flags.
    /// \param original_protection on supported platforms will be set to current memory protection mode. May be null. If not null - always initialize to a best-guess current protection flags value, because on some platforms (like linux) this variable will not be set.
    template<typename Type CPP14(=void*), typename Addr>
    bool mem_protect(Addr p, size_t size, size_t protection, size_t* original_protection=nullptr) { return hooker_mem_protect(reinterpret_cast<void*>(p), size, protection, original_protection) == HOOKER_SUCCESS;  }
    /// Get mnemonic size of current platform.
    template<typename Addr>
    size_t get_mnemonic_size(Addr address, size_t min_size) { return hooker_get_mnemonic_size(reinterpret_cast<void*>(address), min_size); }

    /// Hotpatch a call.
    template<typename OriginalProc CPP14(=void*), typename Addr, typename ProcAddr>
    OriginalProc hotpatch(Addr location, ProcAddr new_proc) { return reinterpret_cast<OriginalProc>(hooker_hotpatch(reinterpret_cast<void*>(location), reinterpret_cast<void*>(new_proc))); }
    /// Unhotpatch a call.
    template<typename Type CPP14(=void*), typename Addr>
    bool unhotpatch(Addr location) { return hooker_unhotpatch(reinterpret_cast<void*>(location)) == HOOKER_SUCCESS; }

    /// Writes a jump or call hook from `address` to `new_proc`.
    /// \param address a pointer where hook should be written
    /// \param new_proc a pointer where hook should point to.
    /// \param flags any of HOOKER_HOOK_* flags. They may not be combined.
    /// \param nops of bytes to nop after hook instruction. Specify -1 to autocalculate.
    /// \returns null on failure or non-null on success.
    template<typename Addr, typename ProcAddr>
    bool hook(Addr address, ProcAddr new_proc, size_t flags, size_t nops=-1) { return hooker_hook(reinterpret_cast<void*>(address), reinterpret_cast<void*>(new_proc), flags, nops) == HOOKER_SUCCESS; }

    /// Redirect call to custom proc.
    /// \param address a start of original call. Warning: It should not contain any relatively-addressed instructions like calls or jumps.
    /// \param new_proc a proc that will be called instead of original one.
    /// \returns pointer, calling which will invoke original proc. It is user's responsibility to call original code when necessary.
    template<typename OriginalProc CPP14(=void*), typename Addr, typename ProcAddr>
    OriginalProc redirect(Addr address, ProcAddr new_proc, size_t flags=0) { return reinterpret_cast<OriginalProc>(hooker_redirect(reinterpret_cast<void*>(address), reinterpret_cast<void*>(new_proc), flags)); }

    /// Unhook a hook created by hooker::hook(.., .., HOOKER_HOOK_REDIRECT, ..).
    /// \param address where hook was written to.
    /// \param original result of hooker::redirect() call.
    template<typename Addr, typename OriginalProc>
    void unhook(Addr address, OriginalProc original) { hooker_unhook(reinterpret_cast<void*>(address), reinterpret_cast<void*>(original)); }

    /// Return address in object's vmt which is pointing to specified method.
    /// \param object is a pointer to a c++ object.
    /// \param method is a pointer to a c++ object method.
    template<typename Addr, typename ProcAddr>
    size_t* get_vmt_address(Addr object, ProcAddr method) { return (size_t*)hooker_get_vmt_address(reinterpret_cast<void*>(object), reinterpret_cast<void*>(method)); }

    /// Find a first occourence of memory pattern.
    /// \param start a pointer to beginning of memory range.
    /// \param size a size of memory range. If size is 0 then entire memory space will be searched. If pattern does not exist this will likely result in a crash. Negative size will search backwards.
    /// \param pattern a array of bytes to search for.
    /// \param pattern_len a length of pattern array.
    /// \param a wildcard byte in the pattern array.
    template<typename Type CPP14(=uint8_t*), typename Addr, typename Pattern>
    Type find_pattern(Addr start, int size, const Pattern* pattern, size_t pattern_len, uint8_t wildcard) { return reinterpret_cast<Type>(hooker_find_pattern(reinterpret_cast<void*>(start), size, reinterpret_cast<uint8_t*>(const_cast<Pattern*>(pattern)), pattern_len, wildcard)); }

    /// Find a first occourence of memory pattern.
    /// \param start a pointer to beginning of memory range.
    /// \param size a size of memory range. If size is 0 then entire memory space will be searched. If pattern does not exist this will likely result in a crash. Negative size will search backwards.
    /// \param patternand wildcard mask.
    template<typename Type CPP14(=uint8_t*), typename Addr, size_t N>
    Type find_pattern(Addr start, int size, const pattern<N>& pattern) { return reinterpret_cast<Type>(hooker_find_pattern_ex(reinterpret_cast<void*>(start), size, pattern.pattern, N, pattern.wildcard)); }

    /// Fill memory with nops (0x90 opcode).
    /// \param start of the memory address.
    /// \param size of the memory that will be filled.
    template<typename Addr>
    void nop(Addr start, size_t size) { hooker_nop(reinterpret_cast<void*>(start), size); }

    /// Write a value to specified memory address.
    /// \param start of the memory address.
    /// \param value to be written.
    template<typename Type, typename Addr>
    void write(Addr address, const Type value) { hooker_write(reinterpret_cast<void*>(address), (void*)&value, sizeof(value)); }

    /// Write an array to specified memory address.
    /// \param start of the memory address.
    /// \param value to be written.
    /// \param count of elements in the array.
    template<typename Type, typename Addr>
    void write(Addr address, const Type* value, size_t count) { hooker_write(reinterpret_cast<void*>(address), (void*)value, sizeof(Type) * count); }

    /// Write bytes to specified memory address.
    /// \param start of the memory address.
    /// \param data to be written.
    /// \param size of data.
    template<typename Addr>
    void write(Addr address, const void* data, size_t size) { hooker_write(reinterpret_cast<void*>(address), data, size); }
};
