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
    CHECK_EXCEPTION_TYPE(etl::bad_optional_access, etl::exception);

    {
        CHECK(!(etl::optional<T>{}.has_value()));
        CHECK(!(etl::optional<T>(etl::nullopt).has_value()));
        CHECK(etl::optional<T>{T{}}.has_value());
        CHECK(etl::optional<T>{T(1)}.has_value());
        auto opt = etl::optional<T>{etl::in_place, T{}};
        CHECK(opt.has_value());
    }

    {
        etl::optional<T> opt{};
        CHECK(!(opt.has_value()));

        // copy ctor
        auto opt1{opt};
        CHECK(!(opt1.has_value()));

        // move ctor
        auto opt2{etl::move(opt)};
        CHECK(!(opt2.has_value()));

        auto opt3{etl::optional<T>{}};
        CHECK(!(opt3.has_value()));
    }

    {
        auto opt = etl::optional<T>{T(1)};
        CHECK(opt.has_value());
        CHECK(opt.value() == T(1));

        // copy ctor
        auto opt1{opt};
        CHECK(opt1.has_value());
        CHECK(opt1.value() == T(1));

        // move ctor
        auto opt2{etl::move(opt)};
        CHECK(opt2.has_value());
        CHECK(opt2.value() == T(1));

        auto opt3{etl::optional<T>{T(1)}};
        CHECK(opt3.has_value());
        CHECK(opt3.value() == T(1));
    }

    {
        etl::optional<T> opt4{};
        CHECK(!(opt4.has_value()));
        opt4 = etl::nullopt;
        CHECK(!(opt4.has_value()));
    }

    {
        etl::optional<T> opt{};
        CHECK(!(opt.has_value()));
        opt = T(1);
        CHECK(opt.has_value());
        CHECK(opt.value() == T(1));
    }

    {
        etl::optional<T> opt{T{}};
        CHECK(opt.has_value());
        CHECK(opt.value() == T{});

        opt = T(1);
        CHECK(opt.has_value());
        CHECK(opt.value() == T(1));
    }

    {
        etl::optional<T> opt{};
        CHECK(!(opt.has_value()));

        // copy assignment
        opt = etl::optional<T>{};
        CHECK(!(opt.has_value()));

        // move assignment
        opt = etl::move(etl::optional<T>{});
        CHECK(!(opt.has_value()));
    }

    {
        etl::optional<T> opt{T(42)};
        CHECK(opt.has_value());
        CHECK(opt.value() == T(42));
        opt = etl::optional<T>{};
        CHECK(!(opt.has_value()));
    }

    {
        etl::optional<T> opt{};
        CHECK(!(opt.has_value()));
        opt = etl::optional<T>{T(42)};
        CHECK(opt.has_value());
        CHECK(opt.value() == T(42));
    }

    {
        etl::optional<T> opt{};
        CHECK(etl::is_trivially_destructible_v<decltype(opt)>);
    }

    {
        struct S {
            S()                                          = default;
            S(S const& /*other*/)                        = default;
            S(S&& /*other*/) noexcept                    = default;
            auto operator=(S const& /*other*/) -> S&     = default;
            auto operator=(S&& /*other*/) noexcept -> S& = default;

            ~S() { }

            T data{};
        };

        etl::optional<S> opt{};
        CHECK(!(etl::is_trivially_destructible_v<S>));
    }

    {
        auto opt = etl::optional<T>{};
        CHECK(!(static_cast<bool>(opt)));

        auto const cOpt = etl::optional<T>{};
        CHECK(!(static_cast<bool>(cOpt)));
    }

    {
        auto opt = etl::optional<T>{T(1)};
        CHECK(static_cast<bool>(opt));

        auto const cOpt = etl::optional<T>{T(1)};
        CHECK(static_cast<bool>(cOpt));
    }

    {
        auto opt = etl::optional<T>{};
        CHECK(opt.operator->() == nullptr);

        auto const cOpt = etl::optional<T>{};
        CHECK(cOpt.operator->() == nullptr);
    }

    {
        auto opt = etl::optional<T>{T(1)};
        CHECK(!(opt.operator->() == nullptr));

        auto const cOpt = etl::optional<T>{T(1)};
        CHECK(!(cOpt.operator->() == nullptr));
    }

    {
        auto opt = etl::optional<T>{};
        CHECK(opt.value_or(T(42)) == T(42));

        auto const cOpt = etl::optional<T>{};
        CHECK(cOpt.value_or(T(42)) == T(42));

        CHECK(etl::optional<T>{}.value_or(T(42)) == T(42));
        CHECK(move(etl::optional<T>(etl::nullopt)).value_or(T(42)) == T(42));
    }

    {
        auto opt = etl::optional<T>{T(1)};
        CHECK(opt.value_or(T(42)) == T(1));

        auto const cOpt = etl::optional<T>{T(1)};
        CHECK(cOpt.value_or(T(42)) == T(1));

        CHECK(etl::optional<T>{T(1)}.value_or(T(42)) == T(1));

        CHECK(etl::move(etl::optional<T>{T(1)}).value_or(T(42)) == T(1));
    }

    {
        etl::optional<T> opt{};
        CHECK(!(opt.has_value()));
        opt.reset();
        CHECK(!(opt.has_value()));
    }

    {
        etl::optional<T> opt{T{}};
        CHECK(opt.has_value());
        opt.reset();
        CHECK(!(opt.has_value()));
    }

    {
        struct S {
            int& counter; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)

            S(int& c) : counter{c} { }

            ~S() { counter++; }

            S(S const& /*other*/)                        = default;
            S(S&& /*other*/) noexcept                    = default;
            auto operator=(S const& /*other*/) -> S&     = default;
            auto operator=(S&& /*other*/) noexcept -> S& = default;
        };

        auto counter = 0;
        etl::optional<S> opt{etl::in_place, counter};
        CHECK(opt.has_value());
        CHECK(counter == 0);
        opt.reset();
        CHECK(!(opt.has_value()));
        CHECK(counter == 1);
    }

    struct SCTOR {
        SCTOR(T xInit, T yInit) : x{xInit}, y{yInit} { }

        T x;
        T y;
    };

    {
        etl::optional<T> opt{};
        CHECK(!(opt.has_value()));
        opt.emplace(T{1});
        CHECK(opt.has_value());
    }

    {
        etl::optional<SCTOR> opt{};
        CHECK(!(opt.has_value()));
        opt.emplace(T{1}, T{2});
        CHECK(opt.has_value());
    }

    {
        etl::optional<T> lhs1{};
        etl::optional<T> rhs1{};
        CHECK(lhs1 == rhs1);
        CHECK(!(lhs1 != rhs1));

        etl::optional<T> lhs2(etl::nullopt);
        etl::optional<T> rhs2(etl::nullopt);
        CHECK(lhs2 == rhs2);
        CHECK(lhs2 == etl::nullopt);
        CHECK(etl::nullopt == rhs2);
        CHECK(!(lhs2 != rhs2));
    }

    {
        etl::optional<T> lhs1{T{42}};
        etl::optional<T> rhs1{T{42}};
        CHECK(lhs1 == rhs1);
        CHECK(!(lhs1 != rhs1));
        CHECK(!(lhs1 == etl::nullopt));
        CHECK(!(etl::nullopt == lhs1));

        etl::optional<T> lhs2{T{0}};
        etl::optional<T> rhs2{T{42}};
        CHECK(lhs2 != rhs2);
        CHECK(lhs2 != etl::nullopt);
        CHECK(etl::nullopt != lhs2);
        CHECK(!(lhs2 == rhs2));

        etl::optional<T> lhs3{T{0}};
        etl::optional<T> rhs3(etl::nullopt);
        CHECK(lhs3 != rhs3);
        CHECK(!(lhs3 == rhs3));
    }

    {
        etl::optional<T> lhs1{};
        etl::optional<T> rhs1{};
        CHECK(!(lhs1 < rhs1));
        CHECK(!(etl::nullopt < rhs1));
        CHECK(!(lhs1 < etl::nullopt));

        etl::optional<T> lhs2(etl::nullopt);
        etl::optional<T> rhs2(etl::nullopt);
        CHECK(!(lhs2 < rhs2));
    }

    {
        etl::optional<T> lhs1{T{42}};
        etl::optional<T> rhs1{T{42}};
        CHECK(!(lhs1 < rhs1));
        CHECK(!(lhs1 < etl::nullopt));
        CHECK(etl::nullopt < rhs1);

        etl::optional<T> lhs2{T{0}};
        etl::optional<T> rhs2{T{42}};
        CHECK(lhs2 < rhs2);

        etl::optional<T> lhs3(etl::nullopt);
        etl::optional<T> rhs3{T{42}};
        CHECK(lhs3 < rhs3);

        CHECK(etl::nullopt < rhs3);
        CHECK(!(lhs3 < etl::nullopt));
    }

    {
        etl::optional<T> lhs1{};
        etl::optional<T> rhs1{};
        CHECK(!(lhs1 > rhs1));

        etl::optional<T> lhs2(etl::nullopt);
        etl::optional<T> rhs2(etl::nullopt);
        CHECK(!(lhs2 > rhs2));
    }

    {
        etl::optional<T> lhs1{T{42}};
        etl::optional<T> rhs1{T{42}};
        CHECK(!(lhs1 > rhs1));

        etl::optional<T> lhs2{T{42}};
        etl::optional<T> rhs2{T{0}};
        CHECK(lhs2 > rhs2);
    }

    {
        etl::optional<T> lhs1{};
        etl::optional<T> rhs1{};
        CHECK(lhs1 <= rhs1);

        etl::optional<T> lhs2(etl::nullopt);
        etl::optional<T> rhs2(etl::nullopt);
        CHECK(lhs2 <= rhs2);
    }

    {
        etl::optional<T> lhs1{T{42}};
        etl::optional<T> rhs1{T{42}};
        CHECK(lhs1 <= rhs1);

        etl::optional<T> lhs2{T{0}};
        etl::optional<T> rhs2{T{42}};
        CHECK(lhs2 <= rhs2);

        etl::optional<T> lhs3(etl::nullopt);
        etl::optional<T> rhs3{T{42}};
        CHECK(lhs3 <= rhs3);
    }

    {
        etl::optional<T> lhs1{};
        etl::optional<T> rhs1{};
        CHECK(lhs1 >= rhs1);

        etl::optional<T> lhs2(etl::nullopt);
        etl::optional<T> rhs2(etl::nullopt);
        CHECK(lhs2 >= rhs2);
    }

    {
        etl::optional<T> lhs1{T{42}};
        etl::optional<T> rhs1{T{42}};
        CHECK(lhs1 >= rhs1);
        CHECK(rhs1 >= lhs1);

        etl::optional<T> lhs2{T{42}};
        etl::optional<T> rhs2{T{0}};
        CHECK(lhs2 >= rhs2);
        CHECK(!(rhs2 >= lhs2));
    }

    {
        etl::optional<T> opt1{};
        etl::optional<T> opt2{};
        CHECK(!(opt1.has_value()));
        CHECK(!(opt2.has_value()));

        opt1.swap(opt2);
        CHECK(!(opt1.has_value()));
        CHECK(!(opt2.has_value()));
    }

    {
        etl::optional<T> opt1{T{1}};
        etl::optional<T> opt2{};
        CHECK(opt1.has_value());
        CHECK(!(opt2.has_value()));

        opt1.swap(opt2);
        CHECK(!(opt1.has_value()));
        CHECK(opt2.has_value());
        CHECK(opt2.value() == 1);

        etl::optional<T> opt3{};
        etl::optional<T> opt4{T{1}};
        CHECK(!(opt3.has_value()));
        CHECK(opt4.has_value());

        opt3.swap(opt4);
        CHECK(opt3.has_value());
        CHECK(opt3.value() == 1);
        CHECK(!(opt4.has_value()));
    }

    {
        etl::optional<T> opt1{T{1}};
        etl::optional<T> opt2{T{2}};
        CHECK(opt1.has_value());
        CHECK(opt2.has_value());

        opt1.swap(opt2);
        CHECK(opt1.has_value());
        CHECK(opt2.has_value());
        CHECK(opt1.value() == 2);
        CHECK(opt2.value() == 1);
    }

    auto opt1 = etl::make_optional(T{42});
    CHECK(etl::is_same_v<typename decltype(opt1)::value_type, T>);

    auto value2 = T{};
    auto opt2   = etl::make_optional(T{value2});
    CHECK(etl::is_same_v<typename decltype(opt2)::value_type, T>);

    auto const value3 = T{};
    auto const opt3   = etl::make_optional(T{value3});
    CHECK(etl::is_same_v<typename decltype(opt3)::value_type, T>);

    struct SMO {
        T data_1;
        int data_2;

        constexpr SMO(T d1, int d2) : data_1{d1}, data_2{d2} { }
    };

    auto const opt143 = etl::make_optional<SMO>(T{42}, 1);
    CHECK(etl::is_same_v<typename decltype(opt143)::value_type, SMO>);

    CHECK(opt143.value().data_1 == T{42});
    CHECK(opt143.value().data_2 == 1);

    {
        etl::optional opt{T{}};
        etl::ignore_unused(opt);
        CHECK_SAME_TYPE(typename decltype(opt)::value_type, T);
    }

    {
        T data{};
        etl::optional opt{data};
        etl::ignore_unused(opt);
        CHECK_SAME_TYPE(typename decltype(opt)::value_type, T);
    }

    {
        T const data{42};
        etl::optional opt44{data};
        etl::ignore_unused(opt44);
        CHECK_SAME_TYPE(typename decltype(opt44)::value_type, T);
    }

    {
        T data[2];
        etl::optional opt55{data};
        etl::ignore_unused(opt55);
        CHECK_SAME_TYPE(typename decltype(opt55)::value_type, T*);
    }

    // and_then
    {
        auto to42 = [](auto) -> etl::optional<int> { return 42; };

        auto empty = etl::optional<T>{};
        CHECK(not static_cast<bool>(empty.and_then(to42)));
        CHECK(not static_cast<bool>(etl::as_const(empty).and_then(to42)));
        CHECK(not static_cast<bool>(etl::optional<T>().and_then(to42)));

        auto one = etl::optional<T>{T(1)};
        CHECK(static_cast<bool>(one.and_then(to42)));
        CHECK(static_cast<bool>(etl::as_const(one).and_then(to42)));
        CHECK(static_cast<bool>(etl::optional<T>(T(1)).and_then(to42)));
    }

    // or_else
    {
        // lvalue
        auto empty = etl::optional<T>{};
        auto zero  = etl::optional<T>{T(0)};
        CHECK(not empty.or_else([] { return etl::optional<T>(); }).has_value());
        CHECK(empty.or_else([] { return etl::optional<T>(T(0)); }).has_value());
        CHECK(zero.or_else([] { return etl::optional<T>(); }).has_value());

        CHECK(not etl::as_const(empty).or_else([] { return etl::optional<T>(); }).has_value());
        CHECK(etl::as_const(empty).or_else([] { return etl::optional<T>(T(0)); }).has_value());
        CHECK(etl::as_const(zero).or_else([] { return etl::optional<T>(); }).has_value());

        // rvalue
        CHECK(not etl::optional<T>().or_else([] { return etl::optional<T>(); }).has_value());
        CHECK(etl::optional<T>(T(0)).or_else([] { return etl::optional<T>(); }).has_value());
        CHECK(etl::optional<T>().or_else([] { return etl::optional<T>(T(0)); }).has_value());
    }

    return true;
}

static auto test_all() -> bool
{
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<float>());
    CHECK(test<double>());

    return true;
}

auto main() -> int
{
    // TODO: [tobi] Add constexpr tests
    CHECK(test_all());
    return 0;
}
