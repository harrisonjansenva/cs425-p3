#include "lab.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

enum
{
  EXIT_OK = 0,
  EXIT_USAGE = 1,
  EXIT_TABLE = 2,
  EXIT_NO_ROUTE = 3
};

static void print_usage(FILE *out)
{
  fprintf(out, "Usage: myapp info <address>/<prefix>\n"
               "       myapp split <network>/<prefix> <count>\n"
               "       myapp lookup <table-file> <address>...\n");
}

static int usage_error(const char *message)
{
  fprintf(stderr, "myapp: %s\n", message);
  print_usage(stderr);
  return EXIT_USAGE;
}

static int cmd_info(const char *text)
{
  cidr_t block;
  if (!cidr_parse(text, &block))
  {
    fprintf(stderr, "myapp: %s: not a valid address/prefix\n", text);
    return EXIT_USAGE;
  }

  char buf[IP_STR_LEN];
  ip_format(block.addr, buf);
  printf("%-11s%s\n", "address", buf);
  printf("%-11s/%u\n", "prefix", (unsigned)block.prefix);
  ip_format(cidr_mask(block.prefix), buf);
  printf("%-11s%s\n", "netmask", buf);
  ip_format(cidr_network(block), buf);
  printf("%-11s%s\n", "network", buf);
  ip_format(cidr_broadcast(block), buf);
  printf("%-11s%s\n", "broadcast", buf);
  ip_format(cidr_first_host(block), buf);
  printf("%-11s%s\n", "first host", buf);
  ip_format(cidr_last_host(block), buf);
  printf("%-11s%s\n", "last host", buf);
  printf("%-11s%" PRIu64 "\n", "hosts", cidr_host_count(block));
  return EXIT_OK;
}

static int cmd_split(const char *text, const char *count_text)
{
  cidr_t block;
  if (!cidr_parse(text, &block))
  {
    fprintf(stderr, "myapp: %s: not a valid network/prefix\n", text);
    return EXIT_USAGE;
  }
  if (!cidr_is_network(block))
  {
    fprintf(stderr, "myapp: %s: has host bits set, so it is not a network\n", text);
    return EXIT_USAGE;
  }

  char *end;
  errno = 0;
  unsigned long count = strtoul(count_text, &end, 10);
  if (count_text[0] < '0' || count_text[0] > '9' || *end != '\0' || errno != 0 ||
      count > UINT32_MAX)
  {
    fprintf(stderr, "myapp: %s: not a valid count\n", count_text);
    return EXIT_USAGE;
  }

  uint32_t n = (uint32_t)count;
  cidr_t subnet;
  if (!cidr_subnet(block, n, 0, &subnet))
  {
    fprintf(stderr, "myapp: cannot split %s into %s subnets: the count must be a power of two "
                    "that leaves a prefix of at most /32\n",
            text, count_text);
    return EXIT_USAGE;
  }

  for (uint32_t i = 0; i < n; i++)
  {
    char buf[CIDR_STR_LEN];
    cidr_subnet(block, n, i, &subnet);
    cidr_format(subnet, buf);
    puts(buf);
  }
  return EXIT_OK;
}

static int cmd_lookup(const char *path, int count, char **addresses)
{
  FILE *in = fopen(path, "r");
  if (in == NULL)
  {
    fprintf(stderr, "myapp: %s: %s\n", path, strerror(errno));
    return EXIT_TABLE;
  }

  fwd_table_t *table = table_create();
  if (table == NULL) // GCOVR_EXCL_START
  {
    fclose(in);
    fprintf(stderr, "myapp: out of memory\n");
    return EXIT_TABLE;
  } // GCOVR_EXCL_STOP

  size_t bad_line = 0;
  bool loaded = table_load(table, in, &bad_line);
  fclose(in);
  if (!loaded)
  {
    if (bad_line != 0)
    {
      fprintf(stderr, "myapp: %s:%zu: not a valid route\n", path, bad_line);
    }
    else
    {
      fprintf(stderr, "myapp: %s: could not be read\n", path);
    }
    table_destroy(table);
    return EXIT_TABLE;
  }

  bool malformed = false;
  bool unreachable = false;
  for (int i = 0; i < count; i++)
  {
    uint32_t addr;
    if (!ip_parse(addresses[i], &addr))
    {
      fprintf(stderr, "myapp: %s: not a valid address\n", addresses[i]);
      malformed = true;
      continue;
    }

    const route_t *route = table_lookup(table, addr);
    if (route == NULL)
    {
      printf("%s unreachable\n", addresses[i]);
      unreachable = true;
    }
    else if (route->gateway != 0)
    {
      char gateway[IP_STR_LEN];
      ip_format(route->gateway, gateway);
      printf("%s via %s dev %s\n", addresses[i], gateway, route->dev);
    }
    else
    {
      printf("%s dev %s\n", addresses[i], route->dev);
    }
  }

  table_destroy(table);
  if (malformed)
  {
    return EXIT_USAGE;
  }
  return unreachable ? EXIT_NO_ROUTE : EXIT_OK;
}

int main(int argc, char **argv)
{
  if (argc == 1)
  {
    print_usage(stdout);
    return EXIT_OK;
  }

  const char *command = argv[1];
  if (strcmp(command, "info") == 0 && argc == 3)
  {
    return cmd_info(argv[2]);
  }
  if (strcmp(command, "split") == 0 && argc == 4)
  {
    return cmd_split(argv[2], argv[3]);
  }
  if (strcmp(command, "lookup") == 0 && argc >= 4)
  {
    return cmd_lookup(argv[2], argc - 3, argv + 3);
  }
  return usage_error("bad command line");
}
