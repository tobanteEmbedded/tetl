// SPDX-License-Identifier: BSL-1.0

#include <etl/variant.hpp>

#include <etl/cstdint.hpp>
#include <etl/type_traits.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

namespace {

constexpr auto test() -> bool
{
    CHECK(sizeof(etl::variant2<etl::int8_t, etl::uint8_t, char8_t>) == sizeof(etl::int8_t) * 2);

    using variant = etl::variant2<int, long, float>;
    CHECK(etl::is_trivially_copyable_v<variant>);
    CHECK(etl::is_trivially_destructible_v<variant>);
    CHECK(etl::get_if<0>(static_cast<variant*>(nullptr)) == nullptr);
    CHECK(etl::get_if<1>(static_cast<variant*>(nullptr)) == nullptr);

    auto v0 = variant{};
    CHECK(v0.index() == 0);
    CHECK(v0[etl::index_v<0>] == 0);
    CHECK(etl::unchecked_get<0>(v0) == 0);
    CHECK(etl::as_const(v0)[etl::index_v<0>] == 0);

    auto v1 = variant{etl::in_place_index<1>, 42};
    CHECK(v1.index() == 1);
    CHECK(v1[etl::index_v<1>] == 42);
    CHECK(etl::unchecked_get<1>(v1) == 42);

    auto const copy = v1;
    CHECK(copy.index() == 1);
    CHECK(copy[etl::index_v<1>] == 42);
    CHECK(*etl::get_if<1>(&copy) == 42);
    CHECK(etl::get_if<0>(&copy) == nullptr);
    CHECK(etl::unchecked_get<1>(copy) == 42);

    auto move = etl::move(v1);
    CHECK(move.index() == 1);
    CHECK(move[etl::index_v<1>] == 42);
    CHECK(*etl::get_if<1>(&move) == 42);
    CHECK(etl::get_if<0>(&move) == nullptr);
    CHECK(etl::unchecked_get<1>(move) == 42);
    CHECK(etl::unchecked_get<1>(etl::move(move)) == 42);

    auto visitor = [](auto v) {
        if constexpr (etl::is_same_v<decltype(v), long>) {
            return long(v);
        } else {
            return 99L;
        }
    };
    CHECK(etl::visit(visitor, move) == 42);

    CHECK(move == copy);
    CHECK_FALSE(move != copy);

    CHECK_FALSE(move == variant{etl::in_place_type<int>, 13});
    CHECK(move != variant{etl::in_place_type<int>, 13});

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
