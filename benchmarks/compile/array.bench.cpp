#if defined(TETL_BENCH_USE_STD)
    #include <algorithm>
    #include <array>
    #include <iterator>

using std::array;
using std::begin;
using std::end;
using std::transform;
#else
    #include <etl/algorithm.hpp>
    #include <etl/array.hpp>
    #include <etl/iterator.hpp>

using etl::array;
using etl::begin;
using etl::end;
using etl::transform;
#endif

template <typename T, size_t Size>
static auto apply_gain_impl(array<T, Size> buffer, T gain) -> void
{
    transform(begin(buffer), end(buffer), begin(buffer), [gain](auto s) { return s * gain; });
}

auto apply_gain(array<float, 16>& buffer, float gain) -> void { apply_gain_impl(buffer, gain); }
auto apply_gain(array<float, 24>& buffer, float gain) -> void { apply_gain_impl(buffer, gain); }
auto apply_gain(array<float, 32>& buffer, float gain) -> void { apply_gain_impl(buffer, gain); }
auto apply_gain(array<float, 64>& buffer, float gain) -> void { apply_gain_impl(buffer, gain); }

auto apply_gain(array<double, 16>& buffer, double gain) -> void { apply_gain_impl(buffer, gain); }
auto apply_gain(array<double, 24>& buffer, double gain) -> void { apply_gain_impl(buffer, gain); }
auto apply_gain(array<double, 32>& buffer, double gain) -> void { apply_gain_impl(buffer, gain); }
auto apply_gain(array<double, 64>& buffer, double gain) -> void { apply_gain_impl(buffer, gain); }
