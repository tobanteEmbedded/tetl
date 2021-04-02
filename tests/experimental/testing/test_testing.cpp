#include "etl/experimental/testing/testing.hpp"

auto main() -> int
{
  auto xc = 2;
  EQUAL(xc, 2);
  NOTEQUAL(xc, 3);
  return 0;
}