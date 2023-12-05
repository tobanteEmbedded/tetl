// SPDX-License-Identifier: BSL-1.0

#include <etl/optional.hpp>

#include <etl/cstdint.hpp>
#include <etl/utility.hpp>
#include <etl/warning.hpp>

#include "testing/exception.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    TEST_EXCEPTION(etl::bad_optional_access, etl::exception);

    {
        assert(!(etl::optional<T> {}.has_value()));
        assert(!(etl::optional<T>(etl::nullopt).has_value()));
        assert((etl::optional<T> {T {}}.has_value()));
        assert((etl::optional<T> {T(1)}.has_value()));
        auto opt = etl::optional<T> {etl::in_place, T {}};
        assert((opt.has_value()));
    }

    {
        etl::optional<T> opt {};
        assert(!(opt.has_value()));

        // copy ctor
        auto opt1 {opt};
        assert(!(opt1.has_value()));

        // move ctor
        auto opt2 {etl::move(opt)};
        assert(!(opt2.has_value()));

        auto opt3 {etl::optional<T> {}};
        assert(!(opt3.has_value()));
    }

    {
        auto opt = etl::optional<T> {T(1)};
        assert((opt.has_value()));
        assert((opt.value() == T(1)));

        // copy ctor
        auto opt1 {opt};
        assert((opt1.has_value()));
        assert((opt1.value() == T(1)));

        // move ctor
        auto opt2 {etl::move(opt)};
        assert((opt2.has_value()));
        assert((opt2.value() == T(1)));

        auto opt3 {etl::optional<T> {T(1)}};
        assert((opt3.has_value()));
        assert((opt3.value() == T(1)));
    }

    {
        etl::optional<T> opt4 {};
        assert(!(opt4.has_value()));
        opt4 = etl::nullopt;
        assert(!(opt4.has_value()));
    }

    {
        etl::optional<T> opt {};
        assert(!(opt.has_value()));
        opt = T(1);
        assert((opt.has_value()));
        assert((opt.value() == T(1)));
    }

    {
        etl::optional<T> opt {T {}};
        assert((opt.has_value()));
        assert((opt.value() == T {}));

        opt = T(1);
        assert((opt.has_value()));
        assert((opt.value() == T(1)));
    }

    {
        etl::optional<T> opt {};
        assert(!(opt.has_value()));

        // copy assignment
        opt = etl::optional<T> {};
        assert(!(opt.has_value()));

        // move assignment
        opt = etl::move(etl::optional<T> {});
        assert(!(opt.has_value()));
    }

    {
        etl::optional<T> opt {T(42)};
        assert((opt.has_value()));
        assert((opt.value() == T(42)));
        opt = etl::optional<T> {};
        assert(!(opt.has_value()));
    }

    {
        etl::optional<T> opt {};
        assert(!(opt.has_value()));
        opt = etl::optional<T> {T(42)};
        assert((opt.has_value()));
        assert((opt.value() == T(42)));
    }

    {
        etl::optional<T> opt {};
        assert((etl::is_trivially_destructible_v<decltype(opt)>));
    }

    {
        struct S {
            S()                                          = default;
            S(S const& /*other*/)                        = default;
            S(S&& /*other*/) noexcept                    = default;
            auto operator=(S const& /*other*/) -> S&     = default;
            auto operator=(S&& /*other*/) noexcept -> S& = default;
            ~S() { }

            T data {};
        };

        etl::optional<S> opt {};
        assert(!(etl::is_trivially_destructible_v<S>));
    }

    {
        auto opt = etl::optional<T> {};
        assert(!(static_cast<bool>(opt)));

        auto const cOpt = etl::optional<T> {};
        assert(!(static_cast<bool>(cOpt)));
    }

    {
        auto opt = etl::optional<T> {T(1)};
        assert((static_cast<bool>(opt)));

        auto const cOpt = etl::optional<T> {T(1)};
        assert((static_cast<bool>(cOpt)));
    }

    {
        auto opt = etl::optional<T> {};
        assert((opt.operator->() == nullptr));

        auto const cOpt = etl::optional<T> {};
        assert((cOpt.operator->() == nullptr));
    }

    {
        auto opt = etl::optional<T> {T(1)};
        assert(!(opt.operator->() == nullptr));

        auto const cOpt = etl::optional<T> {T(1)};
        assert(!(cOpt.operator->() == nullptr));
    }

    {
        auto opt = etl::optional<T> {};
        assert((opt.value_or(T(42)) == T(42)));

        auto const cOpt = etl::optional<T> {};
        assert((cOpt.value_or(T(42)) == T(42)));

        assert((etl::optional<T> {}.value_or(T(42)) == T(42)));
        assert((move(etl::optional<T>(etl::nullopt)).value_or(T(42)) == T(42)));
    }

    {
        auto opt = etl::optional<T> {T(1)};
        assert((opt.value_or(T(42)) == T(1)));

        auto const cOpt = etl::optional<T> {T(1)};
        assert((cOpt.value_or(T(42)) == T(1)));

        assert((etl::optional<T> {T(1)}.value_or(T(42)) == T(1)));

        assert((etl::move(etl::optional<T> {T(1)}).value_or(T(42)) == T(1)));
    }

    {
        etl::optional<T> opt {};
        assert(!(opt.has_value()));
        opt.reset();
        assert(!(opt.has_value()));
    }

    {
        etl::optional<T> opt {T {}};
        assert((opt.has_value()));
        opt.reset();
        assert(!(opt.has_value()));
    }

    {
        struct S {
            int& counter;

            S(int& c) : counter {c} { }
            ~S() { counter++; }
            S(S const& /*other*/)                        = default;
            S(S&& /*other*/) noexcept                    = default;
            auto operator=(S const& /*other*/) -> S&     = default;
            auto operator=(S&& /*other*/) noexcept -> S& = default;
        };

        auto counter = 0;
        etl::optional<S> opt {etl::in_place, counter};
        assert((opt.has_value()));
        assert((counter == 0));
        opt.reset();
        assert(!(opt.has_value()));
        assert((counter == 1));
    }

    struct SCTOR {
        SCTOR(T xInit, T yInit) : x {xInit}, y {yInit} { }

        T x;
        T y;
    };

    {
        etl::optional<T> opt {};
        assert(!(opt.has_value()));
        opt.emplace(T {1});
        assert((opt.has_value()));
    }

    {
        etl::optional<SCTOR> opt {};
        assert(!(opt.has_value()));
        opt.emplace(T {1}, T {2});
        assert((opt.has_value()));
    }

    {
        etl::optional<T> lhs1 {};
        etl::optional<T> rhs1 {};
        assert((lhs1 == rhs1));
        assert(!(lhs1 != rhs1));

        etl::optional<T> lhs2(etl::nullopt);
        etl::optional<T> rhs2(etl::nullopt);
        assert((lhs2 == rhs2));
        assert((lhs2 == etl::nullopt));
        assert((etl::nullopt == rhs2));
        assert(!(lhs2 != rhs2));
    }

    {
        etl::optional<T> lhs1 {T {42}};
        etl::optional<T> rhs1 {T {42}};
        assert((lhs1 == rhs1));
        assert(!(lhs1 != rhs1));
        assert(!(lhs1 == etl::nullopt));
        assert(!(etl::nullopt == lhs1));

        etl::optional<T> lhs2 {T {0}};
        etl::optional<T> rhs2 {T {42}};
        assert((lhs2 != rhs2));
        assert((lhs2 != etl::nullopt));
        assert((etl::nullopt != lhs2));
        assert(!(lhs2 == rhs2));

        etl::optional<T> lhs3 {T {0}};
        etl::optional<T> rhs3(etl::nullopt);
        assert((lhs3 != rhs3));
        assert(!(lhs3 == rhs3));
    }

    {
        etl::optional<T> lhs1 {};
        etl::optional<T> rhs1 {};
        assert(!(lhs1 < rhs1));
        assert(!(etl::nullopt < rhs1));
        assert(!(lhs1 < etl::nullopt));

        etl::optional<T> lhs2(etl::nullopt);
        etl::optional<T> rhs2(etl::nullopt);
        assert(!(lhs2 < rhs2));
    }

    {
        etl::optional<T> lhs1 {T {42}};
        etl::optional<T> rhs1 {T {42}};
        assert(!(lhs1 < rhs1));
        assert(!(lhs1 < etl::nullopt));
        assert((etl::nullopt < rhs1));

        etl::optional<T> lhs2 {T {0}};
        etl::optional<T> rhs2 {T {42}};
        assert((lhs2 < rhs2));

        etl::optional<T> lhs3(etl::nullopt);
        etl::optional<T> rhs3 {T {42}};
        assert((lhs3 < rhs3));

        assert((etl::nullopt < rhs3));
        assert(!(lhs3 < etl::nullopt));
    }

    {
        etl::optional<T> lhs1 {};
        etl::optional<T> rhs1 {};
        assert(!(lhs1 > rhs1));

        etl::optional<T> lhs2(etl::nullopt);
        etl::optional<T> rhs2(etl::nullopt);
        assert(!(lhs2 > rhs2));
    }

    {
        etl::optional<T> lhs1 {T {42}};
        etl::optional<T> rhs1 {T {42}};
        assert(!(lhs1 > rhs1));

        etl::optional<T> lhs2 {T {42}};
        etl::optional<T> rhs2 {T {0}};
        assert((lhs2 > rhs2));
    }

    {
        etl::optional<T> lhs1 {};
        etl::optional<T> rhs1 {};
        assert((lhs1 <= rhs1));

        etl::optional<T> lhs2(etl::nullopt);
        etl::optional<T> rhs2(etl::nullopt);
        assert((lhs2 <= rhs2));
    }

    {
        etl::optional<T> lhs1 {T {42}};
        etl::optional<T> rhs1 {T {42}};
        assert((lhs1 <= rhs1));

        etl::optional<T> lhs2 {T {0}};
        etl::optional<T> rhs2 {T {42}};
        assert((lhs2 <= rhs2));

        etl::optional<T> lhs3(etl::nullopt);
        etl::optional<T> rhs3 {T {42}};
        assert((lhs3 <= rhs3));
    }

    {
        etl::optional<T> lhs1 {};
        etl::optional<T> rhs1 {};
        assert((lhs1 >= rhs1));

        etl::optional<T> lhs2(etl::nullopt);
        etl::optional<T> rhs2(etl::nullopt);
        assert((lhs2 >= rhs2));
    }

    {
        etl::optional<T> lhs1 {T {42}};
        etl::optional<T> rhs1 {T {42}};
        assert((lhs1 >= rhs1));
        assert((rhs1 >= lhs1));

        etl::optional<T> lhs2 {T {42}};
        etl::optional<T> rhs2 {T {0}};
        assert((lhs2 >= rhs2));
        assert(!(rhs2 >= lhs2));
    }

    {
        etl::optional<T> opt1 {};
        etl::optional<T> opt2 {};
        assert(!(opt1.has_value()));
        assert(!(opt2.has_value()));

        opt1.swap(opt2);
        assert(!(opt1.has_value()));
        assert(!(opt2.has_value()));
    }

    {
        etl::optional<T> opt1 {T {1}};
        etl::optional<T> opt2 {};
        assert((opt1.has_value()));
        assert(!(opt2.has_value()));

        opt1.swap(opt2);
        assert(!(opt1.has_value()));
        assert((opt2.has_value()));
        assert((opt2.value() == 1));

        etl::optional<T> opt3 {};
        etl::optional<T> opt4 {T {1}};
        assert(!(opt3.has_value()));
        assert((opt4.has_value()));

        opt3.swap(opt4);
        assert((opt3.has_value()));
        assert((opt3.value() == 1));
        assert(!(opt4.has_value()));
    }

    {
        etl::optional<T> opt1 {T {1}};
        etl::optional<T> opt2 {T {2}};
        assert((opt1.has_value()));
        assert((opt2.has_value()));

        opt1.swap(opt2);
        assert((opt1.has_value()));
        assert((opt2.has_value()));
        assert((opt1.value() == 2));
        assert((opt2.value() == 1));
    }

    auto opt1 = etl::make_optional(T {42});
    assert((etl::is_same_v<typename decltype(opt1)::value_type, T>));

    auto value2 = T {};
    auto opt2   = etl::make_optional(T {value2});
    assert((etl::is_same_v<typename decltype(opt2)::value_type, T>));

    auto const value3 = T {};
    auto const opt3   = etl::make_optional(T {value3});
    assert((etl::is_same_v<typename decltype(opt3)::value_type, T>));

    struct SMO {
        T data_1;
        int data_2;

        constexpr SMO(T d1, int d2) : data_1 {d1}, data_2 {d2} { }
    };

    auto const opt143 = etl::make_optional<SMO>(T {42}, 1);
    assert((etl::is_same_v<typename decltype(opt143)::value_type, SMO>));

    assert((opt143.value().data_1 == T {42}));
    assert((opt143.value().data_2 == 1));
    using etl::is_same_v;

    {
        etl::optional opt {T {}};
        etl::ignore_unused(opt);
        assert((is_same_v<typename decltype(opt)::value_type, T>));
    }

    {
        T data {};
        etl::optional opt {data};
        etl::ignore_unused(opt);
        assert((is_same_v<typename decltype(opt)::value_type, T>));
    }

    {
        T const data {42};
        etl::optional opt44 {data};
        etl::ignore_unused(opt44);
        assert((is_same_v<typename decltype(opt44)::value_type, T>));
    }

    {
        T data[2];
        etl::optional opt55 {data};
        etl::ignore_unused(opt55);
        assert((is_same_v<typename decltype(opt55)::value_type, T*>));
    }

    // and_then
    {
        auto to42 = [](auto) -> etl::optional<int> { return 42; };

        auto empty = etl::optional<T> {};
        assert(not static_cast<bool>(empty.and_then(to42)));
        assert(not static_cast<bool>(etl::as_const(empty).and_then(to42)));
        assert(not static_cast<bool>(etl::optional<T>().and_then(to42)));

        auto one = etl::optional<T> {T(1)};
        assert(static_cast<bool>(one.and_then(to42)));
        assert(static_cast<bool>(etl::as_const(one).and_then(to42)));
        assert(static_cast<bool>(etl::optional<T>(T(1)).and_then(to42)));
    }

    // or_else
    {
        // lvalue
        auto empty = etl::optional<T> {};
        auto zero  = etl::optional<T> {T(0)};
        assert(not empty.or_else([] { return etl::optional<T>(); }).has_value());
        assert(empty.or_else([] { return etl::optional<T>(T(0)); }).has_value());
        assert(zero.or_else([] { return etl::optional<T>(); }).has_value());

        assert(not etl::as_const(empty).or_else([] { return etl::optional<T>(); }).has_value());
        assert(etl::as_const(empty).or_else([] { return etl::optional<T>(T(0)); }).has_value());
        assert(etl::as_const(zero).or_else([] { return etl::optional<T>(); }).has_value());

        // rvalue
        assert(not etl::optional<T>().or_else([] { return etl::optional<T>(); }).has_value());
        assert(etl::optional<T>(T(0)).or_else([] { return etl::optional<T>(); }).has_value());
        assert(etl::optional<T>().or_else([] { return etl::optional<T>(T(0)); }).has_value());
    }

    return true;
}

static auto test_all() -> bool
{
    assert(test<etl::uint8_t>());
    assert(test<etl::int8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::uint64_t>());
    assert(test<etl::int64_t>());
    assert(test<float>());
    assert(test<double>());

    return true;
}

auto main() -> int
{
    assert(test_all());

    // TODO: [tobi] Add constexpr tests
    // static_assert(test_all());
    return 0;
}
