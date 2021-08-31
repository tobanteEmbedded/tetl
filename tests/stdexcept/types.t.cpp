/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/stdexcept.hpp"

#include "etl/exception.hpp"
#include "etl/type_traits.hpp"

#include "helper.hpp"

constexpr auto test() -> bool
{
    assert((etl::is_default_constructible_v<etl::logic_error>));
    assert((etl::is_constructible_v<etl::logic_error, char const*>));
    assert((etl::is_base_of_v<etl::exception, etl::logic_error>));

    assert((etl::is_default_constructible_v<etl::domain_error>));
    assert((etl::is_constructible_v<etl::domain_error, char const*>));
    assert((etl::is_base_of_v<etl::logic_error, etl::domain_error>));
    assert((etl::is_base_of_v<etl::exception, etl::domain_error>));

    assert((etl::is_default_constructible_v<etl::invalid_argument>));
    assert((etl::is_constructible_v<etl::invalid_argument, char const*>));
    assert((etl::is_base_of_v<etl::logic_error, etl::invalid_argument>));
    assert((etl::is_base_of_v<etl::exception, etl::invalid_argument>));

    assert((etl::is_default_constructible_v<etl::length_error>));
    assert((etl::is_constructible_v<etl::length_error, char const*>));
    assert((etl::is_base_of_v<etl::logic_error, etl::length_error>));
    assert((etl::is_base_of_v<etl::exception, etl::length_error>));

    assert((etl::is_default_constructible_v<etl::out_of_range>));
    assert((etl::is_constructible_v<etl::out_of_range, char const*>));
    assert((etl::is_base_of_v<etl::logic_error, etl::out_of_range>));
    assert((etl::is_base_of_v<etl::exception, etl::out_of_range>));

    assert((etl::is_default_constructible_v<etl::runtime_error>));
    assert((etl::is_constructible_v<etl::runtime_error, char const*>));
    assert((etl::is_base_of_v<etl::exception, etl::runtime_error>));

    assert((etl::is_default_constructible_v<etl::range_error>));
    assert((etl::is_constructible_v<etl::range_error, char const*>));
    assert((etl::is_base_of_v<etl::runtime_error, etl::range_error>));
    assert((etl::is_base_of_v<etl::exception, etl::range_error>));

    assert((etl::is_default_constructible_v<etl::overflow_error>));
    assert((etl::is_constructible_v<etl::overflow_error, char const*>));
    assert((etl::is_base_of_v<etl::runtime_error, etl::overflow_error>));
    assert((etl::is_base_of_v<etl::exception, etl::overflow_error>));

    assert((etl::is_default_constructible_v<etl::underflow_error>));
    assert((etl::is_constructible_v<etl::underflow_error, char const*>));
    assert((etl::is_base_of_v<etl::runtime_error, etl::underflow_error>));
    assert((etl::is_base_of_v<etl::exception, etl::underflow_error>));

    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}