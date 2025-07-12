// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.string;
import etl.type_traits;
import etl.utility;
import etl.variant;
#else
    #include <etl/string.hpp>
    #include <etl/type_traits.hpp>
    #include <etl/utility.hpp>
    #include <etl/variant.hpp>
#endif

static constexpr auto test() -> bool
{

    // default
    {
        struct S {
            constexpr S()
                : x{42}
            {
            }

            int x; // NOLINT
        };

        auto v1 = etl::variant<int, float>{};
        CHECK(etl::holds_alternative<int>(v1));
        CHECK_FALSE(etl::holds_alternative<float>(v1));

        auto v2 = etl::variant<float, int>{};
        CHECK(etl::holds_alternative<float>(v2));
        CHECK_FALSE(etl::holds_alternative<int>(v2));

        auto v3 = etl::variant<S, int>{};
        CHECK(etl::holds_alternative<S>(v3));
        CHECK_FALSE(etl::holds_alternative<int>(v3));
        CHECK(etl::get_if<S>(&v3)->x == 42);
    }

    // etl::monostate
    {
        auto var = etl::variant<etl::monostate, int, float>{etl::monostate{}};
        CHECK(etl::holds_alternative<etl::monostate>(var));
        CHECK(*etl::get_if<etl::monostate>(&var) == etl::monostate{});
    }

    // int
    {
        auto v1 = etl::variant<etl::monostate, int, float>{42};
        CHECK(etl::holds_alternative<int>(v1));
        CHECK(*etl::get_if<int>(&v1) == 42);

        auto i  = 143;
        auto v2 = etl::variant<etl::monostate, int, float>{i};
        CHECK(etl::holds_alternative<int>(v2));
        CHECK(*etl::get_if<int>(&v2) == 143);

        auto const ic = 99;
        auto v3       = etl::variant<etl::monostate, float, int>{ic};
        CHECK(etl::holds_alternative<int>(v3));
        CHECK(*etl::get_if<int>(&v3) == 99);
        CHECK(*etl::get_if<2>(&v3) == 99);
    }

    // float
    {
        auto var = etl::variant<etl::monostate, int, float>{143.0F};
        CHECK(etl::holds_alternative<float>(var));
        CHECK(*etl::get_if<float>(&var) == 143.0F);
    }

    // in_place_type_t
    {
        struct Point {
            explicit constexpr Point(float initX, float initY)
                : x{initX}
                , y{initY}
            {
            }

            float x{0.0F};
            float y{0.0F};
        };

        auto const v1 = etl::variant<etl::monostate, int, Point>{etl::in_place_type<Point>, 143.0F, 42.0F};
        CHECK(etl::holds_alternative<Point>(v1));
        CHECK(etl::get_if<Point>(&v1)->x == 143.0F);
        CHECK(etl::get_if<Point>(&v1)->y == 42.0F);

        auto const v2 = etl::variant<etl::monostate, int, Point>{etl::in_place_index<2>, 143.0F, 42.0F};
        CHECK(etl::holds_alternative<Point>(v2));
        CHECK(etl::get_if<Point>(&v2)->x == 143.0F);
        CHECK(etl::get_if<Point>(&v2)->y == 42.0F);
    }

    // 0
    {
        auto var = etl::variant<etl::monostate, int, float>{etl::monostate{}};
        CHECK(var.index() == 0);
    }

    // 1
    {
        auto var = etl::variant<etl::monostate, int, float>{42};
        CHECK(var.index() == 1);
    }

    // 2
    {
        auto var = etl::variant<etl::monostate, int, float>{143.0F};
        CHECK(var.index() == 2);
    }

    // 3
    {
        auto var = etl::variant<etl::monostate, int, float, double>{143.0};
        CHECK(var.index() == 3);
    }

    {
        auto var = etl::variant<etl::monostate, int, float>{42};
        CHECK(etl::holds_alternative<int>(var));
        CHECK(*etl::get_if<int>(&var) == 42);

        auto var2 = etl::variant<etl::monostate, int, float>{143};
        CHECK(etl::holds_alternative<int>(var2));
        CHECK(*etl::get_if<int>(&var2) == 143);

        // var2 = var;
        // CHECK(etl::holds_alternative<int>(var2));
        // CHECK(*etl::get_if<int>(&var2) == 42);

        // var = 42.0F;
        // CHECK(etl::holds_alternative<float>(var));
        // CHECK(etl::get_if<int>(&var) == nullptr);
        // CHECK(*etl::get_if<float>(&var) == 42.0F);
    }

    {
        auto l = etl::variant<int, float>{42};
        auto r = etl::variant<int, float>{143};
        CHECK(*etl::get_if<int>(&l) == 42);
        CHECK(*etl::get_if<int>(&r) == 143);
        CHECK(l != r);
        CHECK(l < r);
        CHECK(l <= r);
        CHECK_FALSE(l > r);
        CHECK_FALSE(l >= r);

        auto other = etl::variant<int, float>{999.0F};
        etl::swap(r, other);
        CHECK(etl::holds_alternative<float>(r));
        CHECK(etl::holds_alternative<int>(other));
    }

    {
        CHECK(not(etl::variant<int>{41} == etl::variant<int>{42}));
        CHECK(etl::variant<int>{42} == etl::variant<int>{42});

        CHECK(etl::variant<int>{41} != etl::variant<int>{42});
        CHECK(etl::variant<int>{41} <= etl::variant<int>{42});
        CHECK(etl::variant<int>{42} >= etl::variant<int>{42});
        CHECK(etl::variant<int>{42} <= etl::variant<int>{42});

        CHECK(not(etl::variant<int>{41} >= etl::variant<int>{42}));
        CHECK(not(etl::variant<int>{42} != etl::variant<int>{42}));
        CHECK(not(etl::variant<int>{42} < etl::variant<int>{42}));
        CHECK(not(etl::variant<int>{42} > etl::variant<int>{42}));
    }

    // mutable
    {
        auto var = etl::variant<etl::monostate, int, float, double>{42};
        CHECK(etl::holds_alternative<int>(var));
        CHECK(not(etl::holds_alternative<etl::monostate>(var)));
        CHECK(not(etl::holds_alternative<float>(var)));
        CHECK(not(etl::holds_alternative<double>(var)));
    }

    // const
    {
        auto const var = etl::variant<etl::monostate, int, float, double>{42.0F};
        CHECK(etl::holds_alternative<float>(var));
        CHECK(not(etl::holds_alternative<int>(var)));
        CHECK(not(etl::holds_alternative<etl::monostate>(var)));
        CHECK(not(etl::holds_alternative<double>(var)));
    }

    {
        auto v1 = etl::variant<etl::monostate, int, float, double>{42};
        CHECK(etl::get_if<int>(&v1) != nullptr);
        CHECK(*etl::get_if<int>(&v1) == 42);
        CHECK(etl::get_if<1>(&v1) != nullptr);
        CHECK(*etl::get_if<1>(&v1) == 42);

        CHECK(etl::get_if<etl::monostate>(&v1) == nullptr);
        CHECK(etl::get_if<float>(&v1) == nullptr);
        CHECK(etl::get_if<double>(&v1) == nullptr);
        CHECK(etl::get_if<0>(&v1) == nullptr);
        CHECK(etl::get_if<2>(&v1) == nullptr);
        CHECK(etl::get_if<3>(&v1) == nullptr);

        auto const v2 = etl::variant<etl::monostate, int, float, double>{42.0F};
        CHECK(etl::get_if<float>(&v2) != nullptr);
        CHECK(*etl::get_if<float>(&v2) == 42.0F);
        CHECK(etl::get_if<2>(&v2) != nullptr);
        CHECK(*etl::get_if<2>(&v2) == 42.0F);

        CHECK(etl::get_if<etl::monostate>(&v2) == nullptr);
        CHECK(etl::get_if<int>(&v2) == nullptr);
        CHECK(etl::get_if<double>(&v2) == nullptr);
        CHECK(etl::get_if<0>(&v2) == nullptr);
        CHECK(etl::get_if<1>(&v2) == nullptr);
        CHECK(etl::get_if<3>(&v2) == nullptr);
    }
    {
        auto v1 = etl::variant<etl::monostate, int, float, double>{42};
        CHECK(etl::unchecked_get<1>(v1) == 42);

        auto const v2 = etl::variant<etl::monostate, int, float, double>{42};
        CHECK(etl::unchecked_get<1>(v2) == 42);
    }
    {
        using t1 = etl::variant<etl::monostate>;
        using t2 = etl::variant<etl::monostate, int>;
        using t3 = etl::variant<etl::monostate, int, float>;
        using t4 = etl::variant<etl::monostate, int, float, double>;

        CHECK(etl::variant_size_v<t1> == 1);
        CHECK(etl::variant_size_v<t2> == 2);
        CHECK(etl::variant_size_v<t3> == 3);
        CHECK(etl::variant_size_v<t4> == 4);

        using t5 = etl::variant<etl::monostate> const;
        using t6 = etl::variant<etl::monostate, int> const;
        using t7 = etl::variant<etl::monostate, int, float> const;
        CHECK(etl::variant_size_v<t5> == 1);
        CHECK(etl::variant_size_v<t6> == 2);
        CHECK(etl::variant_size_v<t7> == 3);
    }

    {
        using t1 = etl::variant<int>;
        CHECK_SAME_TYPE(etl::variant_alternative_t<0, t1>, int);

        using t2 = etl::variant<int>;
        using t3 = etl::variant<int, float>;
        using t4 = etl::variant<int, float, double>;
        CHECK_SAME_TYPE(etl::variant_alternative_t<0, t2>, int);
        CHECK_SAME_TYPE(etl::variant_alternative_t<0, t3>, int);
        CHECK_SAME_TYPE(etl::variant_alternative_t<0, t4>, int);

        CHECK_SAME_TYPE(etl::variant_alternative_t<1, t3>, float);
        CHECK_SAME_TYPE(etl::variant_alternative_t<1, t4>, float);

        CHECK_SAME_TYPE(etl::variant_alternative_t<2, t4>, double);

        using t5 = etl::variant<int, float> const;
        CHECK_SAME_TYPE(etl::variant_alternative_t<0, t5>, int const);
        CHECK_SAME_TYPE(etl::variant_alternative_t<1, t5>, float const);

        using t6 = etl::variant<int, float> volatile;
        CHECK_SAME_TYPE(etl::variant_alternative_t<0, t6>, int volatile);
        CHECK_SAME_TYPE(etl::variant_alternative_t<1, t6>, float volatile);

        using t7 = etl::variant<int, float> const volatile;
        CHECK_SAME_TYPE(etl::variant_alternative_t<0, t7>, int const volatile);
    }

    {
        using variant_t = etl::variant<int, float>;

        auto const v1     = variant_t{143.0F};
        auto const check1 = [](auto val) { return etl::is_same_v<decltype(val), float>; };
        CHECK(etl::visit(check1, v1));

        auto const check2 = [](auto const& val) { return val == 42; };
        CHECK(etl::visit(check2, variant_t{42}));
        CHECK_FALSE(etl::visit(check2, variant_t{99}));

        auto calledInt   = false;
        auto calledFloat = false;
        auto funcs       = etl::overload{
            [&calledFloat](float /*val*/) -> void { calledFloat = true; },
            [&calledInt](int /*val*/) -> void { calledInt = true; },
        };

        auto v3 = variant_t{1};
        etl::visit(funcs, v3);
        CHECK(calledInt);
        CHECK_FALSE(calledFloat);

        calledInt   = false;
        calledFloat = false;

        v3.emplace<float>(1.43F);
        etl::visit(funcs, v3);
        CHECK(calledFloat);
        CHECK_FALSE(calledInt);
    }

    return true;
}

[[nodiscard]] static constexpr auto test_non_trivial() -> bool
{
    struct non_trivial_alternative {
        constexpr explicit non_trivial_alternative(int& v)
            : value{&v}
        {
            *value = 143;
        }

        constexpr ~non_trivial_alternative() noexcept { *value = 42; }

        constexpr non_trivial_alternative(non_trivial_alternative const&) = default;
        constexpr non_trivial_alternative(non_trivial_alternative&&)      = default;

        constexpr auto operator=(non_trivial_alternative const&) -> non_trivial_alternative& = default;
        constexpr auto operator=(non_trivial_alternative&&) -> non_trivial_alternative&      = default;

        int* value;
    };

    using variant_t = etl::variant<int, non_trivial_alternative>;

    auto v = variant_t{};
    CHECK(v.index() == 0);

    auto value = 0;
    v.emplace<non_trivial_alternative>(value);
    CHECK(v.index() == 1);
    CHECK(value == 143);

    v = 99;
    CHECK(value == 42);

    return true;
}

static constexpr auto test_variant_alternative_selector_t() -> bool
{
    using string_t = etl::inplace_string<15>;

    CHECK_SAME_TYPE(etl::detail::variant_alternative_selector_t<int, int, float>, int);
    CHECK_SAME_TYPE(etl::detail::variant_alternative_selector_t<float, int, float>, float);
    CHECK_SAME_TYPE(etl::detail::variant_alternative_selector_t<string_t, int, string_t>, string_t);
    CHECK_SAME_TYPE(etl::detail::variant_alternative_selector_t<char const*, int, string_t>, string_t);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    STATIC_CHECK(test_non_trivial());
    STATIC_CHECK(test_variant_alternative_selector_t());
    return 0;
}
