// SPDX-License-Identifier: BSL-1.0

#ifndef ETL_EXPERIMENTAL_TESTING_MACROS_HPP
#define ETL_EXPERIMENTAL_TESTING_MACROS_HPP

#include "etl/version.hpp"

#include "etl/experimental/testing/assertion_handler.hpp"
#include "etl/experimental/testing/name_and_tags.hpp"
#include "etl/experimental/testing/section.hpp"
#include "etl/experimental/testing/session.hpp"
#include "etl/experimental/testing/source_line_info.hpp"

#include "etl/experimental/mpl/mpl.hpp"

namespace mpl = etl::experimental::mpl;

// The goal of this macro is to avoid evaluation of the arguments, but
// still have the compiler warn on problems inside...
#if !defined(TEST_DETAIL_IGNORE_BUT_WARN)
    #define TEST_DETAIL_IGNORE_BUT_WARN(...)
#endif

#define TEST_DETAIL_TEMPLATE_TEST_CASE2(title, tags, tc, ...)                                                          \
    namespace tc {                                                                                                     \
    template <typename TestType>                                                                                       \
    static auto template_test_case_function() -> void;                                                                 \
    TETL_PP_STRING_VIEW_ARRAY(type_names, __VA_ARGS__);                                                                \
    static auto runner = []() {                                                                                        \
        auto types = ::mpl::make_type_tuple<TETL_PP_EXPAND(__VA_ARGS__)>();                                            \
        ::mpl::for_each_indexed(types, [](auto idx, auto const& t) {                                                   \
            using type_t = typename etl::decay_t<decltype(t)>::name;                                                   \
            etl::test::current_session().add_test(                                                                     \
                etl::test::name_and_tags {                                                                             \
                    title,                                                                                             \
                    tags,                                                                                              \
                },                                                                                                     \
                ::tc::template_test_case_function<type_t>, ::tc::type_names[idx]);                                     \
        });                                                                                                            \
        return true;                                                                                                   \
    }();                                                                                                               \
    }                                                                                                                  \
    template <typename TestType>                                                                                       \
    static auto tc::template_test_case_function()->void

#define TEST_DETAIL_TEMPLATE_TEST_CASE(name, tags, ...)                                                                \
    TEST_DETAIL_TEMPLATE_TEST_CASE2(name, tags, TETL_PP_UNIQUE_NAME(tc), __VA_ARGS__)

#define TEST_DETAIL_TEST_CASE2(tc, ...)                                                                                \
    static auto tc()->void;                                                                                            \
    namespace {                                                                                                        \
    auto TETL_PP_UNIQUE_NAME(tc) = etl::test::auto_reg {                                                               \
        etl::test::name_and_tags { __VA_ARGS__ },                                                                      \
        tc,                                                                                                            \
    };                                                                                                                 \
    }                                                                                                                  \
    static auto tc()->void

#define TEST_DETAIL_TEST_CASE(...) TEST_DETAIL_TEST_CASE2(TETL_PP_UNIQUE_NAME(tc), __VA_ARGS__)

#define TEST_DETAIL_SECTION2(tcs, ...)                                                                                 \
    if (etl::test::section tcs {                                                                                       \
            etl::test::section_info {                                                                                  \
                TEST_DETAIL_SOURCE_LINE_INFO,                                                                          \
                etl::string_view { __VA_ARGS__ },                                                                      \
            },                                                                                                         \
            true,                                                                                                      \
        };                                                                                                             \
        static_cast<bool>(tcs))

#define TEST_DETAIL_SECTION(...) TEST_DETAIL_SECTION2(TETL_PP_UNIQUE_NAME(tc_section), __VA_ARGS__)

#define TEST_DETAIL_CHECK(disposition, ...)                                                                            \
    do {                                                                                                               \
        TEST_DETAIL_IGNORE_BUT_WARN(__VA_ARGS__);                                                                      \
        etl::test::assertion_handler handler {                                                                         \
            TEST_DETAIL_SOURCE_LINE_INFO,                                                                              \
            disposition,                                                                                               \
            TETL_PP_STRINGIFY(__VA_ARGS__),                                                                            \
            static_cast<bool>(!!(__VA_ARGS__)),                                                                        \
        };                                                                                                             \
    } while (false)

// clang-format off
#define TEST_CASE(...)  TEST_DETAIL_TEST_CASE(__VA_ARGS__)
#define TEMPLATE_TEST_CASE(...) TETL_PP_EXPAND(TEST_DETAIL_TEMPLATE_TEST_CASE(__VA_ARGS__))

#define SECTION(...)  TEST_DETAIL_SECTION(__VA_ARGS__)

#define CHECK(...)      TEST_DETAIL_CHECK(etl::test::result_disposition::continue_on_failure, __VA_ARGS__)
#define REQUIRE(...)    TEST_DETAIL_CHECK(etl::test::result_disposition::normal, __VA_ARGS__)

#define CHECK_FALSE(...)    TEST_DETAIL_CHECK((etl::test::result_disposition::flags{etl::test::result_disposition::continue_on_failure | etl::test::result_disposition::false_test }), __VA_ARGS__)
#define REQUIRE_FALSE(...)  TEST_DETAIL_CHECK((etl::test::result_disposition::flags{etl::test::result_disposition::normal | etl::test::result_disposition::false_test }), __VA_ARGS__)

#define CHECK_EQUAL(lhs, rhs)       CHECK((lhs) == (rhs))
#define REQUIRE_EQUAL(lhs, rhs)     REQUIRE((lhs) == (rhs))

#define CHECK_NOT_EQUAL(lhs, rhs)   CHECK_FALSE((lhs) == (rhs))
#define REQUIRE_NOT_EQUAL(lhs, rhs) REQUIRE_FALSE((lhs) == (rhs))
// clang-format on

#endif // ETL_EXPERIMENTAL_TESTING_MACROS_HPP
