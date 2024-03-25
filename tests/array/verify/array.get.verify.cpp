#include <etl/array.hpp>

// clang-format off
// expected-error@*:* {{static assertion failed due to requirement '2UL < 2UL': array index out of range}}
auto v = etl::get<2>(etl::array<int, 2>{}); // expected-note {{in instantiation of function template specialization 'etl::get<2UL, int, 2UL>' requested here}}
