// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

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

#ifndef __has_constexpr_builtin
    #define __has_constexpr_builtin(x) 0
#endif

#define TETL_STRINGIFY_IMPL(str) #str
#define TETL_STRINGIFY(str)      TETL_STRINGIFY_IMPL(str)

#define TETL_CONCAT_IMPL(lhs, rhs) lhs##rhs
#define TETL_CONCAT(lhs, rhs)      TETL_CONCAT_IMPL(lhs, rhs)

#ifdef __COUNTER__
    #define TETL_UNIQUE_NAME(prefix) TETL_CONCAT(prefix, __COUNTER__)
#else
    #define TETL_UNIQUE_NAME(prefix) TETL_CONCAT(prefix, __LINE__)
#endif

#if defined(__GNUC__) or defined(__clang__)
    #define TETL_PP_FUNC_SIG __PRETTY_FUNCTION__
#else
    #define TETL_PP_FUNC_SIG __func__
#endif

#endif // TETL_CONFIG_PREPROCESSOR_HPP
