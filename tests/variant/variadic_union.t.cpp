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

    CHECK(etl::is_trivially_destructible_v<trivial_union_t>);
    CHECK(etl::is_trivially_copyable_v<trivial_union_t>);

    CHECK_FALSE(etl::is_trivially_destructible_v<non_trivial_union_t>);

    auto u = trivial_union_t{etl::index_c<0>, 42};
    CHECK(u[etl::index_c<0>] == 42);
    CHECK(etl::as_const(u)[etl::index_c<0>] == 42);

    u = trivial_union_t{etl::index_c<1>, 99L};
    CHECK(u[etl::index_c<1>] == 99L);
    CHECK(etl::as_const(u)[etl::index_c<1>] == 99L);

    u = trivial_union_t{etl::index_c<2>, static_cast<char const*>(nullptr)};
    CHECK(u[etl::index_c<2>] == nullptr);
    CHECK(etl::as_const(u)[etl::index_c<2>] == nullptr);

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
