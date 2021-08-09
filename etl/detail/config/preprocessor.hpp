// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_DETAIL_CONFIG_PREPROCESSOR_HPP
#define TETL_DETAIL_CONFIG_PREPROCESSOR_HPP

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#ifndef __has_extension
#define __has_extension(x) 0
#endif

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#define TETL_STRINGIFY_IMPL(str) #str
#define TETL_STRINGIFY(str) TETL_STRINGIFY_IMPL(str)

#define TETL_CONCAT_IMPL(s1, s2) s1##s2
#define TETL_CONCAT(s1, s2) TETL_CONCAT_IMPL(s1, s2)

#ifdef __COUNTER__
#define TETL_ANONYMOUS_VAR(name) TETL_CONCAT(name, __COUNTER__)
#else
#define TETL_ANONYMOUS_VAR(name) TETL_CONCAT(name, __LINE__)
#endif

#if defined(__GNUC__)
#define TETL_FUNC_SIG __PRETTY_FUNCTION__
#else
#define TETL_FUNC_SIG __func__
#endif

#endif // TETL_DETAIL_CONFIG_PREPROCESSOR_HPP