// SPDX-License-Identifier: BSL-1.0

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

#define TETL_PP_EMPTY()
#define TETL_PP_DEFER(id)   id TETL_PP_EMPTY()
#define TETL_PP_EXPAND(...) __VA_ARGS__

#define TETL_PP_STRINGIFY_IMPL(str) #str
#define TETL_PP_STRINGIFY(str)      TETL_PP_STRINGIFY_IMPL(str)

#define TETL_PP_CONCAT_IMPL(s1, s2) s1##s2
#define TETL_PP_CONCAT(s1, s2)      TETL_PP_CONCAT_IMPL(s1, s2)

#ifdef __COUNTER__
    #define TETL_PP_UNIQUE_NAME(name) TETL_PP_CONCAT(name, __COUNTER__)
#else
    #define TETL_PP_UNIQUE_NAME(name) TETL_PP_CONCAT(name, __LINE__)
#endif

// clang-format off
#define TETL_PP_NUM_ARGS_(_16, _15, _14, _13, _12, _11, _10, _9, _8, _7, _6, _5, _4, _3, _2, _1, N, ...) N
#define TETL_PP_NUM_ARGS(...) TETL_PP_NUM_ARGS_(__VA_ARGS__, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define TETL_PP_FOREACH(MACRO, ...)         TETL_PP_FOREACH_(TETL_PP_NUM_ARGS(__VA_ARGS__), MACRO, __VA_ARGS__)
#define TETL_PP_FOREACH_(N, M, ...)         TETL_PP_FOREACH_IMPL(N, M, __VA_ARGS__)
#define TETL_PP_FOREACH_IMPL(N, M, ...)     TETL_PP_FOREACH_##N(M, __VA_ARGS__)
#define TETL_PP_FOREACH_1(M, A)             M(A)
#define TETL_PP_FOREACH_2(M, A, ...) M(A)   TETL_PP_FOREACH_1(M, __VA_ARGS__)
#define TETL_PP_FOREACH_3(M, A, ...) M(A)   TETL_PP_FOREACH_2(M, __VA_ARGS__)
#define TETL_PP_FOREACH_4(M, A, ...) M(A)   TETL_PP_FOREACH_3(M, __VA_ARGS__)
#define TETL_PP_FOREACH_5(M, A, ...) M(A)   TETL_PP_FOREACH_4(M, __VA_ARGS__)
#define TETL_PP_FOREACH_6(M, A, ...) M(A)   TETL_PP_FOREACH_5(M, __VA_ARGS__)
#define TETL_PP_FOREACH_7(M, A, ...) M(A)   TETL_PP_FOREACH_6(M, __VA_ARGS__)
#define TETL_PP_FOREACH_8(M, A, ...) M(A)   TETL_PP_FOREACH_7(M, __VA_ARGS__)
#define TETL_PP_FOREACH_9(M, A, ...) M(A)   TETL_PP_FOREACH_8(M, __VA_ARGS__)
#define TETL_PP_FOREACH_10(M, A, ...) M(A)  TETL_PP_FOREACH_9(M, __VA_ARGS__)
#define TETL_PP_FOREACH_11(M, A, ...) M(A)  TETL_PP_FOREACH_10(M, __VA_ARGS__)
#define TETL_PP_FOREACH_12(M, A, ...) M(A)  TETL_PP_FOREACH_11(M, __VA_ARGS__)

// clang-format on

#define TETL_PP_COMMA(X)           X,
#define TETL_PP_COMMA_STRINGIFY(X) TETL_PP_COMMA(TETL_PP_STRINGIFY(X))

#define TETL_PP_STRING_VIEW_ARRAY(var_name, ...)                                                                       \
    static constexpr auto var_name = etl::array<etl::string_view, TETL_PP_NUM_ARGS(__VA_ARGS__)>                       \
    {                                                                                                                  \
        TETL_PP_FOREACH(TETL_PP_COMMA_STRINGIFY, __VA_ARGS__)                                                          \
    }

#if defined(__GNUC__)
    #define TETL_PP_FUNC_SIG __PRETTY_FUNCTION__
#else
    #define TETL_PP_FUNC_SIG __func__
#endif

#endif // TETL_CONFIG_PREPROCESSOR_HPP
