/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#undef NDEBUG

#include "etl/optional.hpp" // for optional
#include "etl/cassert.hpp"  // for TETL_ASSERT

auto main() -> int
{
    using etl::nullopt;
    using etl::optional;

    // construct default (implicit empty)
    auto opt0 = optional<short>();
    TETL_ASSERT(opt0.has_value() == false);
    TETL_ASSERT(static_cast<bool>(opt0) == false);

    // construct explicit empty
    auto opt1 = optional<int>(nullopt);
    TETL_ASSERT(opt1.has_value() == false);
    TETL_ASSERT(static_cast<bool>(opt1) == false);

    // construct explicit with value
    auto opt2 = optional<float>(42.0F);
    TETL_ASSERT(opt2.has_value());
    TETL_ASSERT(static_cast<bool>(opt2));

    // assign copy
    auto const opt3 = opt2;
    TETL_ASSERT(opt3.has_value());
    TETL_ASSERT(static_cast<bool>(opt3));

    // assign move
    auto const opt4 = move(opt2);
    TETL_ASSERT(opt4.has_value());
    TETL_ASSERT(static_cast<bool>(opt4));

    // value & value_or
    static_assert(optional<int>().value_or(1) == 1);
    static_assert(optional<int>(1).value() == 1);

    // Fails to compile, or raises an exception if invoked at runtime
    // static_assert(optional<int>().value());
    // TETL_ASSERT(optional<int>().value());

    // reset
    auto opt5 = optional<float>(1.0F);
    TETL_ASSERT(opt5.has_value());
    opt5.reset();
    TETL_ASSERT(opt5.has_value() == false);

    return 0;
}
