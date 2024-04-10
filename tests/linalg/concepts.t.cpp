// SPDX-License-Identifier: BSL-1.0

#include <etl/linalg.hpp>

#include <etl/complex.hpp>

#include "testing/testing.hpp"

namespace ns {
struct my_complex {
    float real;
    float imag;
};

[[maybe_unused]] static auto real(my_complex const& cplx) -> float { return cplx.real; }

[[maybe_unused]] static auto imag(my_complex const& cplx) -> float { return cplx.imag; }

[[maybe_unused]] static auto conj(my_complex const& cplx) -> my_complex { return {cplx.real, -cplx.imag}; }

struct my_string { };

} // namespace ns

namespace detail = etl::linalg::detail;

static constexpr auto test_abs() -> bool
{
    CHECK_FALSE(detail::has_adl_abs<unsigned char>);
    CHECK_FALSE(detail::has_adl_abs<unsigned short>);
    CHECK_FALSE(detail::has_adl_abs<unsigned int>);
    CHECK_FALSE(detail::has_adl_abs<unsigned long>);
    CHECK_FALSE(detail::has_adl_abs<unsigned long long>);

    // CHECK(detail::has_adl_abs<signed char>);
    // CHECK(detail::has_adl_abs<signed short>);
    CHECK(detail::has_adl_abs<signed int>);
    CHECK(detail::has_adl_abs<signed long>);
    CHECK(detail::has_adl_abs<signed long long>);

    CHECK(detail::has_adl_abs<float>);
    CHECK(detail::has_adl_abs<double>);
    CHECK(detail::has_adl_abs<long double>);

    CHECK_FALSE(detail::has_adl_abs<ns::my_complex>); // no overload defined
    CHECK(detail::has_adl_abs<etl::complex<float>>);
    CHECK(detail::has_adl_abs<etl::complex<double>>);
    CHECK(detail::has_adl_abs<etl::complex<long double>>);

    CHECK_FALSE(detail::has_adl_abs<ns::my_string>);

    return true;
}

static constexpr auto test_real() -> bool
{
    // CHECK_FALSE(detail::has_adl_real<signed char>);
    // CHECK_FALSE(detail::has_adl_real<short>);
    // CHECK_FALSE(detail::has_adl_real<int>);
    // CHECK_FALSE(detail::has_adl_real<long>);
    // CHECK_FALSE(detail::has_adl_real<long long>);

    // CHECK_FALSE(detail::has_adl_real<unsigned char>);
    // CHECK_FALSE(detail::has_adl_real<unsigned short>);
    // CHECK_FALSE(detail::has_adl_real<unsigned int>);
    // CHECK_FALSE(detail::has_adl_real<unsigned long>);
    // CHECK_FALSE(detail::has_adl_real<unsigned long long>);
    // CHECK_FALSE(detail::has_adl_real<int>);

    // CHECK_FALSE(detail::has_adl_real<float>);
    // CHECK_FALSE(detail::has_adl_real<double>);
    // CHECK_FALSE(detail::has_adl_real<long double>);

    CHECK(detail::has_adl_real<ns::my_complex>);
    CHECK(detail::has_adl_real<etl::complex<float>>);
    CHECK(detail::has_adl_real<etl::complex<double>>);
    CHECK(detail::has_adl_real<etl::complex<long double>>);

    CHECK_FALSE(detail::has_adl_real<ns::my_string>);

    return true;
}

static constexpr auto test_imag() -> bool
{
    // CHECK_FALSE(detail::has_adl_imag<signed char>);
    // CHECK_FALSE(detail::has_adl_imag<short>);
    // CHECK_FALSE(detail::has_adl_imag<int>);
    // CHECK_FALSE(detail::has_adl_imag<long>);
    // CHECK_FALSE(detail::has_adl_imag<long long>);

    // CHECK_FALSE(detail::has_adl_imag<unsigned char>);
    // CHECK_FALSE(detail::has_adl_imag<unsigned short>);
    // CHECK_FALSE(detail::has_adl_imag<unsigned int>);
    // CHECK_FALSE(detail::has_adl_imag<unsigned long>);
    // CHECK_FALSE(detail::has_adl_imag<unsigned long long>);
    // CHECK_FALSE(detail::has_adl_imag<int>);

    // CHECK_FALSE(detail::has_adl_imag<float>);
    // CHECK_FALSE(detail::has_adl_imag<double>);
    // CHECK_FALSE(detail::has_adl_imag<long double>);

    CHECK(detail::has_adl_imag<ns::my_complex>);
    CHECK(detail::has_adl_imag<etl::complex<float>>);
    CHECK(detail::has_adl_imag<etl::complex<double>>);
    CHECK(detail::has_adl_imag<etl::complex<long double>>);

    CHECK_FALSE(detail::has_adl_imag<ns::my_string>);

    return true;
}

static constexpr auto test_conj() -> bool
{
    // CHECK_FALSE(detail::has_adl_conj<signed char>);
    // CHECK_FALSE(detail::has_adl_conj<short>);
    // CHECK_FALSE(detail::has_adl_conj<int>);
    // CHECK_FALSE(detail::has_adl_conj<long>);
    // CHECK_FALSE(detail::has_adl_conj<long long>);

    // CHECK_FALSE(detail::has_adl_conj<unsigned char>);
    // CHECK_FALSE(detail::has_adl_conj<unsigned short>);
    // CHECK_FALSE(detail::has_adl_conj<unsigned int>);
    // CHECK_FALSE(detail::has_adl_conj<unsigned long>);
    // CHECK_FALSE(detail::has_adl_conj<unsigned long long>);
    // CHECK_FALSE(detail::has_adl_conj<int>);

    // CHECK_FALSE(detail::has_adl_conj<float>);
    // CHECK_FALSE(detail::has_adl_conj<double>);
    // CHECK_FALSE(detail::has_adl_conj<long double>);

    CHECK(detail::has_adl_conj<ns::my_complex>);
    CHECK(detail::has_adl_conj<etl::complex<float>>);
    CHECK(detail::has_adl_conj<etl::complex<double>>);
    CHECK(detail::has_adl_conj<etl::complex<long double>>);

    CHECK_FALSE(detail::has_adl_imag<ns::my_string>);

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test_abs());
    CHECK(test_real());
    CHECK(test_imag());
    CHECK(test_conj());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return EXIT_SUCCESS;
}
