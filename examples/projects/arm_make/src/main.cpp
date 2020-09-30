#include "etl/algorithm.hpp"
#include "etl/array.hpp"
#include "etl/vector.hpp"
#include "etl/warning.hpp"

auto foo() { return etl::static_vector<float, 64> {}; }

extern "C" int main(int argc, char** argv)
{
    etl::ignore_unused(argv);
    auto arr = etl::array {1, 2, 3, argc};
    etl::sort(begin(arr), end(arr));
    return arr.back();
}