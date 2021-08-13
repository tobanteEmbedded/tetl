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

#ifndef TETL_CONFIG_PREPROCESSOR_HPP
#define TETL_CONFIG_PREPROCESSOR_HPP

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

#define TETL_EMPTY()
#define TETL_DEFER(id) id TETL_EMPTY()
#define TETL_EXPAND(...) __VA_ARGS__

#define TETL_STRINGIFY_IMPL(str) #str
#define TETL_STRINGIFY(str) TETL_STRINGIFY_IMPL(str)

#define TETL_CONCAT_IMPL(s1, s2) s1##s2
#define TETL_CONCAT(s1, s2) TETL_CONCAT_IMPL(s1, s2)

#ifdef __COUNTER__
#define TETL_ANONYMOUS_VAR(name) TETL_CONCAT(name, __COUNTER__)
#else
#define TETL_ANONYMOUS_VAR(name) TETL_CONCAT(name, __LINE__)
#endif

#define TETL_NUM_ARGS_(                                                        \
    _12, _11, _10, _9, _8, _7, _6, _5, _4, _3, _2, _1, N, ...)                 \
    N
#define TETL_NUM_ARGS(...)                                                     \
    TETL_NUM_ARGS_(__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define TETL_FOREACH(MACRO, ...)                                               \
    TETL_FOREACH_(TETL_NUM_ARGS(__VA_ARGS__), MACRO, __VA_ARGS__)
#define TETL_FOREACH_(N, M, ...) TETL_FOREACH__(N, M, __VA_ARGS__)
#define TETL_FOREACH__(N, M, ...) TETL_FOREACH_##N(M, __VA_ARGS__)
#define TETL_FOREACH_1(M, A) M(A)
#define TETL_FOREACH_2(M, A, ...) M(A) TETL_FOREACH_1(M, __VA_ARGS__)
#define TETL_FOREACH_3(M, A, ...) M(A) TETL_FOREACH_2(M, __VA_ARGS__)
#define TETL_FOREACH_4(M, A, ...) M(A) TETL_FOREACH_3(M, __VA_ARGS__)
#define TETL_FOREACH_5(M, A, ...) M(A) TETL_FOREACH_4(M, __VA_ARGS__)
#define TETL_FOREACH_6(M, A, ...) M(A) TETL_FOREACH_5(M, __VA_ARGS__)
#define TETL_FOREACH_7(M, A, ...) M(A) TETL_FOREACH_6(M, __VA_ARGS__)
#define TETL_FOREACH_8(M, A, ...) M(A) TETL_FOREACH_7(M, __VA_ARGS__)
#define TETL_FOREACH_9(M, A, ...) M(A) TETL_FOREACH_8(M, __VA_ARGS__)
#define TETL_FOREACH_10(M, A, ...) M(A) TETL_FOREACH_9(M, __VA_ARGS__)
#define TETL_FOREACH_11(M, A, ...) M(A) TETL_FOREACH_10(M, __VA_ARGS__)
#define TETL_FOREACH_12(M, A, ...) M(A) TETL_FOREACH_11(M, __VA_ARGS__)

#define TETL_STRINGIFY_ALL(...) TETL_FOREACH(TETL_STRINGIFY, __VA_ARGS__)

#define TETL_COMMA(X) X,
#define TETL_COMMA_STRINGIFY(X) TETL_COMMA(TETL_STRINGIFY(X))

#define TETL_STRING_LITERAL_ARRAY(var_name, ...)                               \
    static constexpr auto var_name                                             \
        = ::etl::array<::etl::string_view, TETL_NUM_ARGS(__VA_ARGS__)>         \
    {                                                                          \
        TETL_FOREACH(TETL_COMMA_STRINGIFY, __VA_ARGS__)                        \
    }

#if defined(__GNUC__)
#define TETL_FUNC_SIG __PRETTY_FUNCTION__
#else
#define TETL_FUNC_SIG __func__
#endif

#endif // TETL_CONFIG_PREPROCESSOR_HPP