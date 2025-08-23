// SPDX-License-Identifier: BSL-1.0

#include <etl/cassert.hpp>
#include <etl/optional.hpp>

auto main() -> int
{
    using etl::nullopt;
    using etl::optional;

    // construct default (implicit empty)
    auto opt0 = optional<short>();
    assert(opt0.has_value() == false);
    assert(static_cast<bool>(opt0) == false);

    // construct explicit empty
    auto opt1 = optional<int>(nullopt);
    assert(opt1.has_value() == false);
    assert(static_cast<bool>(opt1) == false);

    // construct explicit with value
    auto opt2 = optional<float>(42.0F);
    assert(opt2.has_value());
    assert(static_cast<bool>(opt2));

    // assign copy
    auto const opt3 = opt2;
    assert(opt3.has_value());
    assert(static_cast<bool>(opt3));

    // assign move
    auto const opt4 = etl::move(opt2);
    assert(opt4.has_value());
    assert(static_cast<bool>(opt4));

    // value & value_or
    assert(optional<int>().value_or(1) == 1);

    // Fails to compile, or raises an exception if invoked at runtime
    // static_assert(optional<int>().value());
    // assert(optional<int>().value());

    // reset
    auto opt5 = optional<float>(1.0F);
    assert(opt5.has_value());
    opt5.reset();
    assert(opt5.has_value() == false);

    return 0;
}
