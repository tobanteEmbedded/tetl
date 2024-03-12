// SPDX-License-Identifier: BSL-1.0

#include <etl/variant.hpp>

#include <etl/type_traits.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

namespace {

struct non_trivial_dtor {
    non_trivial_dtor() = default;

    ~non_trivial_dtor() { } // NOLINT
};

constexpr auto test() -> bool
{
    using trivial_union_t     = etl::variadic_union<int, long, char const*>;
    using non_trivial_union_t = etl::variadic_union<int, long, char const*, non_trivial_dtor>;

    ASSERT(etl::is_trivially_destructible_v<trivial_union_t>);
    ASSERT(etl::is_trivially_copyable_v<trivial_union_t>);

    ASSERT(not etl::is_trivially_destructible_v<non_trivial_union_t>);

    auto u = trivial_union_t{etl::index_constant<0>, 42};
    ASSERT(u[etl::index_constant<0>] == 42);
    ASSERT(etl::as_const(u)[etl::index_constant<0>] == 42);

    u = trivial_union_t{etl::index_constant<1>, 99L};
    ASSERT(u[etl::index_constant<1>] == 99L);
    ASSERT(etl::as_const(u)[etl::index_constant<1>] == 99L);

    u = trivial_union_t{etl::index_constant<2>, static_cast<char const*>(nullptr)};
    ASSERT(u[etl::index_constant<2>] == nullptr);
    ASSERT(etl::as_const(u)[etl::index_constant<2>] == nullptr);

    return true;
}

} // namespace

auto main() -> int
{
    ASSERT(test());
    static_assert(test());
    return 0;
}
