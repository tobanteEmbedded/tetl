#if defined(TETL_BENCH_USE_STD)
    #include <tuple>

using std::tuple;
#else
    #include <etl/tuple.hpp>

using etl::tuple;
#endif

auto get_0(tuple<int> const& t) -> int { return get<0>(t); }
auto get_1(tuple<int, double> const& t) -> double { return get<1>(t); }

auto get_0(tuple<float> const& t) -> float { return get<0>(t); }
auto get_1(tuple<float, double> const& t) -> double { return get<1>(t); }

auto get_0(tuple<short> const& t) -> short { return get<0>(t); }
auto get_1(tuple<short, double> const& t) -> double { return get<1>(t); }

auto get_0(tuple<char, short, int, long, long long, float, double> const& t) -> char { return get<0>(t); }
auto get_1(tuple<char, short, int, long, long long, float, double> const& t) -> short { return get<1>(t); }
auto get_2(tuple<char, short, int, long, long long, float, double> const& t) -> int { return get<2>(t); }
auto get_3(tuple<char, short, int, long, long long, float, double> const& t) -> long { return get<3>(t); }
