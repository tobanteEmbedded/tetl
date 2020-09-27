/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_INTRINSICS_HPP
#define TAETL_INTRINSICS_HPP

#define TAETL_IS_ENUM(Type) __is_enum(Type)
#define TAETL_IS_CLASS(Type) __is_class(Type)
#define TAETL_IS_UNION(Type) __is_union(Type)

#define TAETL_HAS_VIRTUAL_DESTRUCTOR(Type) __has_virtual_destructor(Type)

#define TAETL_IS_TRIVIAL_CONSTRUCTIBLE(Type) __is_trivially_constructible(Type)

// Macro not available in GCC8.2
#if defined(__is_nothrow_constructible)
#define TAETL_IS_NOTHROW_CONSTRUCTIBLE(Type) __is_nothrow_constructible(Type)
#else
#define TAETL_IS_NOTHROW_CONSTRUCTIBLE(Type) true
#endif

#define TAETL_IS_TRIVIAL_DESTRUCTIBLE(Type) __has_trivial_destructor(Type)

#define TAETL_IS_ASSIGNABLE(T, Arg) __is_assignable(T, Arg)
#define TAETL_IS_TRIVIALLY_ASSIGNABLE(T, Arg) __is_trivially_assignable(T, Arg)

#endif  // TAETL_INTRINSICS_HPP