// SPDX-License-Identifier: BSL-1.0

#include <etl/variant.hpp>

#include <etl/cstdint.hpp>
#include <etl/string.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

static auto test() -> bool
{
    using etl::int8_t;
    using etl::monostate;
    using etl::uint16_t;
    using etl::uint32_t;
    using etl::uint64_t;
    using etl::uint8_t;
    using etl::variant;

    {

        struct S {
            uint32_t data[4];
        };

        ASSERT(sizeof(variant<monostate>) == 2);
        ASSERT(sizeof(variant<monostate, uint8_t>) == 2);
        ASSERT(sizeof(variant<monostate, int8_t, uint8_t>) == 2);
        ASSERT(sizeof(variant<monostate, char, int8_t, uint8_t>) == 2);

        ASSERT(sizeof(variant<monostate, uint16_t>) == 4);
        ASSERT(sizeof(variant<monostate, char, int8_t, uint16_t>) == 4);

        ASSERT(sizeof(variant<monostate, uint32_t>) == 8);
        ASSERT(sizeof(variant<monostate, uint32_t, uint32_t>) == 8);
        ASSERT(sizeof(variant<monostate, uint32_t, uint64_t>) == 16);
        ASSERT(sizeof(variant<monostate, S, uint64_t>) == 24);
    }

    // default
    {
        struct S {
            constexpr S() : x{42} { }

            int x; // NOLINT
        };

        auto v1 = etl::variant<int, float>{};
        ASSERT(etl::holds_alternative<int>(v1));
        ASSERT(not etl::holds_alternative<float>(v1));

        auto v2 = etl::variant<float, int>{};
        ASSERT(etl::holds_alternative<float>(v2));
        ASSERT(not etl::holds_alternative<int>(v2));

        auto v3 = etl::variant<S, int>{};
        ASSERT(etl::holds_alternative<S>(v3));
        ASSERT(not etl::holds_alternative<int>(v3));
        ASSERT(etl::get_if<S>(&v3)->x == 42);
    }

    // monostate
    {
        auto var = variant<monostate, int, float>{monostate{}};
        ASSERT(etl::holds_alternative<monostate>(var));
        ASSERT(*etl::get_if<monostate>(&var) == monostate{});
    }

    // int
    {
        auto v1 = variant<monostate, int, float>{42};
        ASSERT(etl::holds_alternative<int>(v1));
        ASSERT(*etl::get_if<int>(&v1) == 42);

        auto i  = 143;
        auto v2 = variant<monostate, int, float>{i};
        ASSERT(etl::holds_alternative<int>(v2));
        ASSERT(*etl::get_if<int>(&v2) == 143);

        auto const ic = 99;
        auto v3       = variant<monostate, float, int>{ic};
        ASSERT(etl::holds_alternative<int>(v3));
        ASSERT(*etl::get_if<int>(&v3) == 99);
        ASSERT(*etl::get_if<2>(&v3) == 99);
    }

    // float
    {
        auto var = variant<monostate, int, float>{143.0F};
        ASSERT(etl::holds_alternative<float>(var));
        ASSERT(*etl::get_if<float>(&var) == 143.0F);
    }

    // in_place_type_t
    {
        struct Point {
            explicit constexpr Point(float initX, float initY) : x{initX}, y{initY} { }

            float x{0.0F};
            float y{0.0F};
        };

        auto v1 = variant<monostate, int, Point>{
            etl::in_place_type<Point>,
            143.0F,
            42.0F,
        };

        ASSERT(etl::holds_alternative<Point>(v1));
        ASSERT(etl::get_if<Point>(&v1)->x == 143.0F);
        ASSERT(etl::get_if<Point>(&v1)->y == 42.0F);

        auto v2 = variant<monostate, int, Point>{
            etl::in_place_index<2>,
            143.0F,
            42.0F,
        };

        ASSERT(etl::holds_alternative<Point>(v2));
        ASSERT(etl::get_if<Point>(&v2)->x == 143.0F);
        ASSERT(etl::get_if<Point>(&v2)->y == 42.0F);
    }

    // 0
    {
        auto var = variant<monostate, int, float>{monostate{}};
        ASSERT(var.index() == 0);
    }

    // 1
    {
        auto var = variant<monostate, int, float>{42};
        ASSERT(var.index() == 1);
    }

    // 2
    {
        auto var = variant<monostate, int, float>{143.0F};
        ASSERT(var.index() == 2);
    }

    // 3
    {
        auto var = variant<monostate, int, float, double>{143.0};
        ASSERT(var.index() == 3);
    }

    {
        auto var = variant<monostate, int, float>{42};
        ASSERT(etl::holds_alternative<int>(var));
        ASSERT(*etl::get_if<int>(&var) == 42);

        auto var2 = variant<monostate, int, float>{143};
        ASSERT(etl::holds_alternative<int>(var2));
        ASSERT(*etl::get_if<int>(&var2) == 143);

        var2 = var;
        ASSERT(etl::holds_alternative<int>(var2));
        ASSERT(*etl::get_if<int>(&var2) == 42);

        // var = 42.0F;
        // ASSERT(etl::holds_alternative<float>(var));
        // ASSERT(etl::get_if<int>(&var) == nullptr);
        // ASSERT(*etl::get_if<float>(&var) == 42.0F);
    }

    {
        auto l = variant<int, float>{42};
        auto r = variant<int, float>{143};
        ASSERT(*etl::get_if<int>(&l) == 42);
        ASSERT(*etl::get_if<int>(&r) == 143);

        l.swap(r);
        ASSERT(*etl::get_if<int>(&l) == 143);
        ASSERT(*etl::get_if<int>(&r) == 42);

        auto other = variant<int, float>{999.0F};
        etl::swap(l, other);
        ASSERT(etl::holds_alternative<float>(l));
        ASSERT(etl::holds_alternative<int>(other));
    }

    {
        ASSERT(not(variant<int>{41} == variant<int>{42}));
        ASSERT(variant<int>{42} == variant<int>{42});

        ASSERT(variant<int>{41} != variant<int>{42});
        ASSERT(variant<int>{41} <= variant<int>{42});
        ASSERT(variant<int>{42} >= variant<int>{42});
        ASSERT(variant<int>{42} <= variant<int>{42});

        ASSERT(not(variant<int>{41} >= variant<int>{42}));
        ASSERT(not(variant<int>{42} != variant<int>{42}));
        ASSERT(not(variant<int>{42} < variant<int>{42}));
        ASSERT(not(variant<int>{42} > variant<int>{42}));
    }

    // mutable
    {
        auto var = variant<monostate, int, float, double>{42};
        ASSERT(etl::holds_alternative<int>(var));
        ASSERT(not(etl::holds_alternative<monostate>(var)));
        ASSERT(not(etl::holds_alternative<float>(var)));
        ASSERT(not(etl::holds_alternative<double>(var)));
    }

    // const
    {
        auto const var = variant<monostate, int, float, double>{42.0F};
        ASSERT(etl::holds_alternative<float>(var));
        ASSERT(not(etl::holds_alternative<int>(var)));
        ASSERT(not(etl::holds_alternative<monostate>(var)));
        ASSERT(not(etl::holds_alternative<double>(var)));
    }

    {
        auto v1 = variant<etl::monostate, int, float, double>{42};
        ASSERT(etl::get_if<int>(&v1) != nullptr);
        ASSERT(*etl::get_if<int>(&v1) == 42);
        ASSERT(etl::get_if<1>(&v1) != nullptr);
        ASSERT(*etl::get_if<1>(&v1) == 42);

        ASSERT(etl::get_if<etl::monostate>(&v1) == nullptr);
        ASSERT(etl::get_if<float>(&v1) == nullptr);
        ASSERT(etl::get_if<double>(&v1) == nullptr);
        ASSERT(etl::get_if<0>(&v1) == nullptr);
        ASSERT(etl::get_if<2>(&v1) == nullptr);
        ASSERT(etl::get_if<3>(&v1) == nullptr);

        auto const v2 = variant<monostate, int, float, double>{42.0F};
        ASSERT(etl::get_if<float>(&v2) != nullptr);
        ASSERT(*etl::get_if<float>(&v2) == 42.0F);
        ASSERT(etl::get_if<2>(&v2) != nullptr);
        ASSERT(*etl::get_if<2>(&v2) == 42.0F);

        ASSERT(etl::get_if<monostate>(&v2) == nullptr);
        ASSERT(etl::get_if<int>(&v2) == nullptr);
        ASSERT(etl::get_if<double>(&v2) == nullptr);
        ASSERT(etl::get_if<0>(&v2) == nullptr);
        ASSERT(etl::get_if<1>(&v2) == nullptr);
        ASSERT(etl::get_if<3>(&v2) == nullptr);
    }
    {
        auto v1 = variant<monostate, int, float, double>{42};
        ASSERT(etl::get<1>(v1) == 42);
        ASSERT(etl::get<int>(v1) == 42);

        auto const v2 = variant<monostate, int, float, double>{42};
        ASSERT(etl::get<int>(v2) == 42);
        ASSERT(etl::get<1>(v2) == 42);
    }
    {
        using t1 = variant<monostate>;
        using t2 = variant<monostate, int>;
        using t3 = variant<monostate, int, float>;
        using t4 = variant<monostate, int, float, double>;

        ASSERT(etl::variant_size_v<t1> == 1);
        ASSERT(etl::variant_size_v<t2> == 2);
        ASSERT(etl::variant_size_v<t3> == 3);
        ASSERT(etl::variant_size_v<t4> == 4);

        using t5 = variant<monostate> const;
        using t6 = variant<monostate, int> const;
        using t7 = variant<monostate, int, float> const;
        ASSERT(etl::variant_size_v<t5> == 1);
        ASSERT(etl::variant_size_v<t6> == 2);
        ASSERT(etl::variant_size_v<t7> == 3);
    }

    {
        using etl::is_same_v;
        using etl::variant_alternative_t;

        using t1 = variant<int>;
        ASSERT(is_same_v<variant_alternative_t<0, t1>, int>);

        using t2 = variant<int>;
        using t3 = variant<int, float>;
        using t4 = variant<int, float, double>;
        ASSERT(is_same_v<variant_alternative_t<0, t2>, int>);
        ASSERT(is_same_v<variant_alternative_t<0, t3>, int>);
        ASSERT(is_same_v<variant_alternative_t<0, t4>, int>);

        ASSERT(is_same_v<variant_alternative_t<1, t3>, float>);
        ASSERT(is_same_v<variant_alternative_t<1, t4>, float>);

        ASSERT(is_same_v<variant_alternative_t<2, t4>, double>);

        using t5 = variant<int, float> const;
        ASSERT(is_same_v<variant_alternative_t<0, t5>, int const>);
        ASSERT(is_same_v<variant_alternative_t<1, t5>, float const>);

        using t6 = variant<int, float> volatile;
        ASSERT(is_same_v<variant_alternative_t<0, t6>, int volatile>);
        ASSERT(is_same_v<variant_alternative_t<1, t6>, float volatile>);

        using t7 = variant<int, float> const volatile;
        ASSERT(is_same_v<variant_alternative_t<0, t7>, int const volatile>);
    }

    {
        using T         = int;
        using variant_t = etl::variant<T, float>;
        auto v1         = variant_t{143.0F};
        auto check1     = etl::overload{
            [](float val) { ASSERT(val == 143.0F); },
            [](T /*val*/) { ASSERT(false); },
        };
        etl::visit(check1, v1);

        auto v2 = variant_t{T{42}};
        etl::visit([](auto const& val) { ASSERT(val == T{42}); }, v2);

        auto calledT     = false;
        auto calledFloat = false;
        auto funcs       = etl::overload{
            [&calledFloat](float /*val*/) -> void { calledFloat = true; },
            [&calledT](T /*val*/) -> void { calledT = true; },
        };

        auto v3 = variant_t{T{1}};
        etl::visit(funcs, v3);
        ASSERT(calledT);
        ASSERT(not calledFloat);
    }

    return true;
}

[[nodiscard]] static auto test_non_trivial() -> bool
{
    struct non_trivial_alternative {
        explicit non_trivial_alternative(int& v) : value{&v} { *value = 143; }

        ~non_trivial_alternative() noexcept { *value = 42; }

        non_trivial_alternative(non_trivial_alternative const&) = default;
        non_trivial_alternative(non_trivial_alternative&&)      = default;

        auto operator=(non_trivial_alternative const&) -> non_trivial_alternative& = default;
        auto operator=(non_trivial_alternative&&) -> non_trivial_alternative&      = default;

        int* value;
    };

    using variant_t = etl::variant<int, non_trivial_alternative>;

    auto v = variant_t{};
    ASSERT(v.index() == 0);

    auto value = 0;
    v.emplace<non_trivial_alternative>(value);
    ASSERT(v.index() == 1);
    ASSERT(value == 143);

    v = 99;
    ASSERT(value == 42);

    return true;
}

constexpr auto test_variant_ctor_type_selector_t() -> bool
{
    using string_t = etl::static_string<15>;

    ASSERT(etl::is_same_v<etl::detail::variant_ctor_type_selector_t<int, int, float>, int>);
    ASSERT(etl::is_same_v<etl::detail::variant_ctor_type_selector_t<float, int, float>, float>);
    ASSERT(etl::is_same_v<etl::detail::variant_ctor_type_selector_t<string_t, int, string_t>, string_t>);
    ASSERT(etl::is_same_v<etl::detail::variant_ctor_type_selector_t<char const*, int, string_t>, string_t>);

    return true;
}

auto main() -> int
{
    ASSERT(test());
    ASSERT(test_non_trivial());

    ASSERT(test_variant_ctor_type_selector_t());
    static_assert(test_variant_ctor_type_selector_t());

    return 0;
}
