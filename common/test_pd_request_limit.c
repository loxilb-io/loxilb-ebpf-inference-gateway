#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "sockproxy_pd.h"

int main(int argc, char **argv)
{
  assert(argc == 2);
  size_t expected = (size_t)strtoull(argv[1], NULL, 10);
  assert(pd_max_request_body_bytes() == expected);
  assert(pd_max_request_body_bytes() == expected);
  printf("PASS P/D request byte limit %zu\n", expected);
  return 0;
}
