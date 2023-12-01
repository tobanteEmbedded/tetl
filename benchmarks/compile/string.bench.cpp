#if defined(TETL_BENCH_USE_STD)
    #include <string>
    #include <string_view>
using std::size_t;
using std::string;
using std::string_view;
#else
    #include <etl/string.hpp>
    #include <etl/string_view.hpp>

using string = etl::static_string<128>;
using etl::size_t;
using etl::string_view;
#endif

auto ctor_0(char const* str) -> string { return string {str}; }
auto ctor_1(string_view str) -> string { return string {str}; }

auto at(string_view str, size_t index) { return str[index]; }

auto contains(string_view haystack, string_view needle) { return haystack.find(needle) != string_view::npos; }
