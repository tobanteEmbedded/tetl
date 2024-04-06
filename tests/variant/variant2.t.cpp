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

    struct non_trivial {
        constexpr explicit non_trivial(int v) : value{v} { }

        constexpr non_trivial(non_trivial const& other) noexcept : value{other.value} { }

        constexpr non_trivial(non_trivial&& other) noexcept : value{other.value} { }

        constexpr auto operator=(non_trivial const& other) noexcept -> non_trivial&
        {
            value = other.value;
            return *this;
        }

        constexpr auto operator=(non_trivial&& other) noexcept -> non_trivial&
        {
            value = other.value;
            return *this;
        }

        constexpr ~non_trivial() { } // NOLINT

        constexpr operator int() const noexcept { return value; }

        int value;
    };

    {
        using var_t = etl::variant2<int, float, non_trivial>;
        auto var    = var_t{etl::in_place_type<non_trivial>, 42};
        CHECK(var.index() == 2);
        CHECK(etl::visit_with_index([](auto v) { return static_cast<etl::size_t>(v.index); }, var) == 2);
        CHECK(etl::visit_with_index([](auto v) { return static_cast<int>(v.value()); }, var) == 42);

        auto var2 = var_t(var);

        auto const var3 = var_t(etl::move(var));
        auto const var4 = var3;
        CHECK(var2 == var3);
        CHECK(var2 == var4);

        var2.emplace<0>(143);
        CHECK(var2.index() == 0);

        auto var5 = etl::move(var2);
        CHECK(var5.index() == 0);
        CHECK(var5[etl::index_v<0>] == 143);

        var5.emplace<float>(1.43F);
        CHECK(etl::holds_alternative<float>(var5));
        CHECK(var5[etl::index_v<1>] == 1.43F);
    }

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
