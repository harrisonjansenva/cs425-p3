#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "harness/unity.h"
#include "../src/lab.h"

void setUp(void) {}

void tearDown(void) {}

/* ---------------------------------------------------------------- helpers */

static cidr_t block(const char *text)
{
  cidr_t b = {0, 0};
  TEST_ASSERT_TRUE(cidr_parse(text, &b));
  return b;
}

static uint32_t ip(const char *text)
{
  uint32_t a = 0;
  TEST_ASSERT_TRUE(ip_parse(text, &a));
  return a;
}

static void assert_ip(const char *expected, uint32_t addr)
{
  char buf[IP_STR_LEN];
  ip_format(addr, buf);
  TEST_ASSERT_EQUAL_STRING(expected, buf);
}

static route_t make_route(const char *dest, const char *gateway, const char *dev)
{
  route_t r;
  memset(&r, 0, sizeof r);
  r.dest = block(dest);
  r.gateway = strcmp(gateway, "direct") == 0 ? 0 : ip(gateway);
  strncpy(r.dev, dev, DEV_NAME_LEN - 1);
  return r;
}

static bool load_text(fwd_table_t *table, const char *text, size_t *bad_line)
{
  FILE *f = tmpfile();
  TEST_ASSERT_NOT_NULL(f);
  fputs(text, f);
  rewind(f);
  bool ok = table_load(table, f, bad_line);
  fclose(f);
  return ok;
}

static const char *EXAMPLE =
    "# destination      gateway          device\n"
    "default            132.178.227.1    eno1\n"
    "132.178.227.0/25   direct           eno1\n"
    "10.0.0.0/8         10.1.0.1         eth1\n"
    "10.1.0.0/16        direct           eth1\n"
    "10.1.2.0/24        direct           eth2\n"
    "10.1.2.128/25      10.1.2.1         eth2   # a router behind eth2\n"
    "192.168.0.0/16     10.1.0.1         eth1\n";

/* ----------------------------------------------------------------- Task 1 */

void test_ip_parse_valid(void)
{
  uint32_t a = 1;
  TEST_ASSERT_TRUE(ip_parse("0.0.0.0", &a));
  TEST_ASSERT_EQUAL_HEX32(0, a);
  TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &a));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, a);
  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &a));
  TEST_ASSERT_EQUAL_HEX32(0xC0A8010A, a);
  TEST_ASSERT_TRUE(ip_parse("10.0.200.9", NULL));
}

void test_ip_parse_rejects_malformed(void)
{
  const char *bad[] = {"",         "1.2.3",    "1.2.3.4.5", "1..2.3",   "256.1.1.1", "010.0.0.1",
                       "1.2.3.4x", " 1.2.3.4", "1.2.3.4 ",  "+1.2.3.4", "-1.2.3.4",  "1.2.3.",
                       ".1.2.3",   "a.b.c.d",  "1,2,3,4",   "1.2.3.256", "1.2.3.0004", "1.2.3.4\n",
                       "1.2.3.4/24", "1111.2.3.4", "1.2.3.00"};
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
  {
    uint32_t a = 0xDEADBEEF;
    TEST_ASSERT_FALSE_MESSAGE(ip_parse(bad[i], &a), bad[i]);
    TEST_ASSERT_EQUAL_HEX32(0xDEADBEEF, a);
  }
  uint32_t a = 0xDEADBEEF;
  TEST_ASSERT_FALSE(ip_parse(NULL, &a));
  TEST_ASSERT_EQUAL_HEX32(0xDEADBEEF, a);
}

void test_ip_format(void)
{
  assert_ip("0.0.0.0", 0);
  assert_ip("255.255.255.255", 0xFFFFFFFF);
  assert_ip("192.168.1.10", 0xC0A8010A);
  assert_ip("1.2.3.4", 0x01020304);
}

void test_cidr_parse_valid(void)
{
  cidr_t b;
  TEST_ASSERT_TRUE(cidr_parse("192.168.1.0/24", &b));
  TEST_ASSERT_EQUAL_HEX32(0xC0A80100, b.addr);
  TEST_ASSERT_EQUAL_UINT8(24, b.prefix);
  TEST_ASSERT_TRUE(cidr_parse("132.178.227.11/25", &b));
  TEST_ASSERT_EQUAL_HEX32(0x84B2E30B, b.addr);
  TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &b));
  TEST_ASSERT_EQUAL_UINT8(0, b.prefix);
  TEST_ASSERT_TRUE(cidr_parse("255.255.255.255/32", &b));
  TEST_ASSERT_EQUAL_UINT8(32, b.prefix);
  TEST_ASSERT_TRUE(cidr_parse("10.0.0.0/8", NULL));
}

void test_cidr_parse_rejects_malformed(void)
{
  const char *bad[] = {"1.2.3.4/33", "1.2.3.4/024", "1.2.3.4/",   "1.2.3/24",  "1.2.3.4",
                       "1.2.3.4/x",  "1.2.3.4/-1",  "1.2.3.4/2 4", "1.2.3.4/24x", "1.2.3.4//24",
                       "/24",        "",            "256.1.1.1/8", "1.2.3.4/100", "1.2.3.4/1.2",
                       "1.2.3.4/+8"};
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
  {
    cidr_t b = {0xDEADBEEF, 7};
    TEST_ASSERT_FALSE_MESSAGE(cidr_parse(bad[i], &b), bad[i]);
    TEST_ASSERT_EQUAL_HEX32(0xDEADBEEF, b.addr);
    TEST_ASSERT_EQUAL_UINT8(7, b.prefix);
  }
  cidr_t b = {5, 5};
  TEST_ASSERT_FALSE(cidr_parse(NULL, &b));
  TEST_ASSERT_EQUAL_HEX32(5, b.addr);
}

void test_cidr_format(void)
{
  char buf[CIDR_STR_LEN];
  cidr_format(block("192.168.1.0/24"), buf);
  TEST_ASSERT_EQUAL_STRING("192.168.1.0/24", buf);
  cidr_format(block("132.178.227.11/25"), buf);
  TEST_ASSERT_EQUAL_STRING("132.178.227.11/25", buf);
  cidr_format(block("0.0.0.0/0"), buf);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0/0", buf);
  cidr_format(block("255.255.255.255/32"), buf);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255/32", buf);
  cidr_t over = {0x01020304, 40};
  cidr_format(over, buf);
  TEST_ASSERT_EQUAL_STRING("1.2.3.4/32", buf);
}

/* ----------------------------------------------------------------- Task 2 */

void test_cidr_mask(void)
{
  TEST_ASSERT_EQUAL_HEX32(0x00000000, cidr_mask(0));
  TEST_ASSERT_EQUAL_HEX32(0x80000000, cidr_mask(1));
  TEST_ASSERT_EQUAL_HEX32(0xFF000000, cidr_mask(8));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFF00, cidr_mask(24));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFF80, cidr_mask(25));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFE, cidr_mask(31));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(32));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(33));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(255));
}

void test_network_and_broadcast(void)
{
  cidr_t b = block("132.178.227.11/25");
  assert_ip("132.178.227.0", cidr_network(b));
  assert_ip("132.178.227.127", cidr_broadcast(b));
  b = block("0.0.0.0/0");
  assert_ip("0.0.0.0", cidr_network(b));
  assert_ip("255.255.255.255", cidr_broadcast(b));
  b = block("10.1.2.3/32");
  assert_ip("10.1.2.3", cidr_network(b));
  assert_ip("10.1.2.3", cidr_broadcast(b));
  b = block("10.1.2.3/31");
  assert_ip("10.1.2.2", cidr_network(b));
  assert_ip("10.1.2.3", cidr_broadcast(b));
}

void test_first_and_last_host(void)
{
  cidr_t b = block("132.178.227.11/25");
  assert_ip("132.178.227.1", cidr_first_host(b));
  assert_ip("132.178.227.126", cidr_last_host(b));
  b = block("0.0.0.0/0");
  assert_ip("0.0.0.1", cidr_first_host(b));
  assert_ip("255.255.255.254", cidr_last_host(b));
  b = block("10.0.0.0/30");
  assert_ip("10.0.0.1", cidr_first_host(b));
  assert_ip("10.0.0.2", cidr_last_host(b));
  b = block("10.0.0.0/31");
  assert_ip("10.0.0.0", cidr_first_host(b));
  assert_ip("10.0.0.1", cidr_last_host(b));
  b = block("10.0.0.7/32");
  assert_ip("10.0.0.7", cidr_first_host(b));
  assert_ip("10.0.0.7", cidr_last_host(b));
}

void test_host_count(void)
{
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(4294967294), cidr_host_count(block("0.0.0.0/0")));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(2147483646), cidr_host_count(block("0.0.0.0/1")));
  TEST_ASSERT_EQUAL_UINT64(254, cidr_host_count(block("192.168.1.0/24")));
  TEST_ASSERT_EQUAL_UINT64(126, cidr_host_count(block("132.178.227.11/25")));
  TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(block("10.0.0.0/30")));
  TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(block("10.0.0.0/31")));
  TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(block("10.0.0.1/32")));
}

void test_contains(void)
{
  cidr_t b = block("132.178.227.11/25");
  TEST_ASSERT_TRUE(cidr_contains(b, ip("132.178.227.50")));
  TEST_ASSERT_TRUE(cidr_contains(b, ip("132.178.227.0")));
  TEST_ASSERT_TRUE(cidr_contains(b, ip("132.178.227.127")));
  TEST_ASSERT_FALSE(cidr_contains(b, ip("132.178.227.128")));
  TEST_ASSERT_FALSE(cidr_contains(b, ip("132.178.227.200")));

  b = block("0.0.0.0/0");
  TEST_ASSERT_TRUE(cidr_contains(b, 0));
  TEST_ASSERT_TRUE(cidr_contains(b, 0xFFFFFFFF));
  TEST_ASSERT_TRUE(cidr_contains(b, ip("8.8.8.8")));

  b = block("1.2.3.4/32");
  TEST_ASSERT_TRUE(cidr_contains(b, ip("1.2.3.4")));
  TEST_ASSERT_FALSE(cidr_contains(b, ip("1.2.3.5")));

  b = block("1.2.3.4/31");
  TEST_ASSERT_TRUE(cidr_contains(b, ip("1.2.3.4")));
  TEST_ASSERT_TRUE(cidr_contains(b, ip("1.2.3.5")));
  TEST_ASSERT_FALSE(cidr_contains(b, ip("1.2.3.6")));
}

void test_is_network(void)
{
  TEST_ASSERT_TRUE(cidr_is_network(block("192.168.1.0/24")));
  TEST_ASSERT_FALSE(cidr_is_network(block("192.168.1.5/24")));
  TEST_ASSERT_TRUE(cidr_is_network(block("0.0.0.0/0")));
  TEST_ASSERT_FALSE(cidr_is_network(block("0.0.0.1/0")));
  TEST_ASSERT_TRUE(cidr_is_network(block("10.0.0.2/31")));
  TEST_ASSERT_FALSE(cidr_is_network(block("10.0.0.3/31")));
  TEST_ASSERT_TRUE(cidr_is_network(block("255.255.255.255/32")));
}

void test_subnet(void)
{
  const char *expected[] = {"192.168.1.0/26", "192.168.1.64/26", "192.168.1.128/26",
                            "192.168.1.192/26"};
  for (uint32_t i = 0; i < 4; i++)
  {
    cidr_t out;
    char buf[CIDR_STR_LEN];
    TEST_ASSERT_TRUE(cidr_subnet(block("192.168.1.0/24"), 4, i, &out));
    cidr_format(out, buf);
    TEST_ASSERT_EQUAL_STRING(expected[i], buf);
  }

  cidr_t out;
  TEST_ASSERT_TRUE(cidr_subnet(block("10.0.0.0/8"), 1, 0, &out));
  TEST_ASSERT_EQUAL_UINT8(8, out.prefix);
  TEST_ASSERT_EQUAL_HEX32(0x0A000000, out.addr);

  /* 0.0.0.0/0 into 2^31 pieces: the last one is 255.255.255.254/31. */
  TEST_ASSERT_TRUE(cidr_subnet(block("0.0.0.0/0"), UINT32_C(1) << 31, (UINT32_C(1) << 31) - 1, &out));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFE, out.addr);
  TEST_ASSERT_EQUAL_UINT8(31, out.prefix);

  TEST_ASSERT_TRUE(cidr_subnet(block("0.0.0.0/0"), 2, 1, &out));
  TEST_ASSERT_EQUAL_HEX32(0x80000000, out.addr);
  TEST_ASSERT_EQUAL_UINT8(1, out.prefix);

  /* Splitting down to single hosts. */
  TEST_ASSERT_TRUE(cidr_subnet(block("10.0.0.0/30"), 4, 3, &out));
  TEST_ASSERT_EQUAL_HEX32(0x0A000003, out.addr);
  TEST_ASSERT_EQUAL_UINT8(32, out.prefix);
}

void test_subnet_failures(void)
{
  cidr_t out = {0xDEADBEEF, 9};
  TEST_ASSERT_FALSE(cidr_subnet(block("192.168.1.0/24"), 4, 0, NULL));
  TEST_ASSERT_FALSE(cidr_subnet(block("192.168.1.5/24"), 4, 0, &out));
  TEST_ASSERT_FALSE(cidr_subnet(block("192.168.1.0/24"), 0, 0, &out));
  TEST_ASSERT_FALSE(cidr_subnet(block("192.168.1.0/24"), 3, 0, &out));
  TEST_ASSERT_FALSE(cidr_subnet(block("192.168.1.0/24"), 6, 0, &out));
  TEST_ASSERT_FALSE(cidr_subnet(block("192.168.1.0/24"), 512, 0, &out));
  TEST_ASSERT_FALSE(cidr_subnet(block("192.168.1.1/32"), 2, 0, &out));
  TEST_ASSERT_FALSE(cidr_subnet(block("192.168.1.0/24"), 4, 4, &out));
  TEST_ASSERT_FALSE(cidr_subnet(block("192.168.1.0/24"), 4, UINT32_MAX, &out));
  TEST_ASSERT_FALSE(cidr_subnet(block("0.0.0.0/0"), UINT32_C(1) << 31, UINT32_C(1) << 31, &out));
  cidr_t over = {0x01020304, 40};
  TEST_ASSERT_FALSE(cidr_subnet(over, 2, 0, &out));
  TEST_ASSERT_EQUAL_HEX32(0xDEADBEEF, out.addr);
  TEST_ASSERT_EQUAL_UINT8(9, out.prefix);
}

/* ----------------------------------------------------------------- Task 3 */

void test_route_parse_valid(void)
{
  route_t r;
  TEST_ASSERT_TRUE(route_parse("default 132.178.227.1 eno1", &r));
  TEST_ASSERT_EQUAL_HEX32(0, r.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(0, r.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(0x84B2E301, r.gateway);
  TEST_ASSERT_EQUAL_STRING("eno1", r.dev);

  TEST_ASSERT_TRUE(route_parse("10.1.2.128/25\tdirect\teth2\r\n", &r));
  TEST_ASSERT_EQUAL_HEX32(0x0A010280, r.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(25, r.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(0, r.gateway);
  TEST_ASSERT_EQUAL_STRING("eth2", r.dev);

  TEST_ASSERT_TRUE(route_parse("   10.0.0.0/8 \t 10.1.0.1   x  \n", &r));
  TEST_ASSERT_EQUAL_STRING("x", r.dev);
  TEST_ASSERT_EQUAL_HEX32(0x0A010001, r.gateway);

  TEST_ASSERT_TRUE(route_parse("0.0.0.0/0 direct abcdefghijklmno", &r));
  TEST_ASSERT_EQUAL_STRING("abcdefghijklmno", r.dev);
  TEST_ASSERT_TRUE(route_parse("1.2.3.4/32 direct eth0", NULL));
}

void test_route_parse_rejects_malformed(void)
{
  const char *bad[] = {
      "",
      "   \n",
      "default",
      "default direct",
      "default direct eth0 extra",
      "default direct eth0 # comment",
      "10.1.2.5/24 direct eth0",         /* host bits set */
      "10.1.2.0 direct eth0",            /* no prefix */
      "10.1.2.0/33 direct eth0",
      "bogus direct eth0",
      "default direct0 eth0",
      "default 1.2.3 eth0",
      "default 010.0.0.1 eth0",
      "default Direct eth0",
      "Default direct eth0",
      "default direct abcdefghijklmnop", /* 16 characters */
      "default direct abcdefghijklmnopqrstuvwxyz0123456789",
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
  {
    route_t r;
    memset(&r, 0xAB, sizeof r);
    route_t copy = r;
    TEST_ASSERT_FALSE_MESSAGE(route_parse(bad[i], &r), bad[i]);
    TEST_ASSERT_EQUAL_MEMORY(&copy, &r, sizeof r);
  }
  route_t r;
  TEST_ASSERT_FALSE(route_parse(NULL, &r));
}

void test_table_create_destroy(void)
{
  fwd_table_t *t = table_create();
  TEST_ASSERT_NOT_NULL(t);
  TEST_ASSERT_EQUAL_UINT(0, table_count(t));
  table_destroy(t);
  table_destroy(NULL);
  TEST_ASSERT_EQUAL_UINT(0, table_count(NULL));
}

void test_table_add(void)
{
  fwd_table_t *t = table_create();
  route_t r = make_route("10.0.0.0/8", "10.1.0.1", "eth1");
  TEST_ASSERT_TRUE(table_add(t, &r));
  TEST_ASSERT_EQUAL_UINT(1, table_count(t));

  /* Duplicate block, even with different gateway/device. */
  route_t dup = make_route("10.0.0.0/8", "direct", "eth9");
  TEST_ASSERT_FALSE(table_add(t, &dup));
  /* Same address, different prefix is a different block. */
  route_t other = make_route("10.0.0.0/16", "direct", "eth9");
  TEST_ASSERT_TRUE(table_add(t, &other));
  /* Same prefix, different address is a different block. */
  route_t other2 = make_route("11.0.0.0/8", "direct", "eth9");
  TEST_ASSERT_TRUE(table_add(t, &other2));
  TEST_ASSERT_EQUAL_UINT(3, table_count(t));

  route_t hostbits = {{0x0A000001, 8}, 0, "eth0"};
  TEST_ASSERT_FALSE(table_add(t, &hostbits));
  TEST_ASSERT_FALSE(table_add(t, NULL));
  TEST_ASSERT_FALSE(table_add(NULL, &r));
  TEST_ASSERT_EQUAL_UINT(3, table_count(t));

  /* The table keeps a copy. */
  strcpy(r.dev, "changed");
  TEST_ASSERT_EQUAL_STRING("eth1", table_lookup(t, ip("10.200.0.1"))->dev);
  table_destroy(t);
}

void test_table_grows(void)
{
  fwd_table_t *t = table_create();
  for (uint32_t i = 0; i < 100; i++)
  {
    route_t r = {{i << 8, 24}, 0, "eth0"};
    TEST_ASSERT_TRUE(table_add(t, &r));
  }
  TEST_ASSERT_EQUAL_UINT(100, table_count(t));
  for (uint32_t i = 0; i < 100; i++)
  {
    const route_t *r = table_lookup(t, (i << 8) | 77);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_HEX32(i << 8, r->dest.addr);
  }
  TEST_ASSERT_NULL(table_lookup(t, 100u << 8));
  table_destroy(t);
}

void test_table_load_example_and_lookup(void)
{
  fwd_table_t *t = table_create();
  size_t bad = 99;
  TEST_ASSERT_TRUE(load_text(t, EXAMPLE, &bad));
  TEST_ASSERT_EQUAL_UINT(0, bad);
  TEST_ASSERT_EQUAL_UINT(7, table_count(t));

  const route_t *r = table_lookup(t, ip("132.178.227.50"));
  TEST_ASSERT_EQUAL_STRING("eno1", r->dev);
  TEST_ASSERT_EQUAL_HEX32(0, r->gateway);

  r = table_lookup(t, ip("8.8.8.8"));
  TEST_ASSERT_EQUAL_UINT8(0, r->dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(ip("132.178.227.1"), r->gateway);

  r = table_lookup(t, ip("10.1.2.5"));
  TEST_ASSERT_EQUAL_UINT8(24, r->dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(0, r->gateway);

  /* Inside /8, /16, /24 and /25: the /25 must win. */
  r = table_lookup(t, ip("10.1.2.200"));
  TEST_ASSERT_EQUAL_UINT8(25, r->dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(ip("10.1.2.1"), r->gateway);
  TEST_ASSERT_EQUAL_STRING("eth2", r->dev);

  r = table_lookup(t, ip("10.1.9.9"));
  TEST_ASSERT_EQUAL_UINT8(16, r->dest.prefix);
  r = table_lookup(t, ip("10.9.9.9"));
  TEST_ASSERT_EQUAL_UINT8(8, r->dest.prefix);
  r = table_lookup(t, ip("192.168.77.1"));
  TEST_ASSERT_EQUAL_UINT8(16, r->dest.prefix);

  TEST_ASSERT_NULL(table_lookup(NULL, ip("10.1.2.5")));
  table_destroy(t);
}

void test_lookup_independent_of_order(void)
{
  const char *lines[] = {"10.0.0.0/8 10.1.0.1 eth1",   "10.1.0.0/16 direct eth1",
                         "10.1.2.0/24 direct eth2",    "10.1.2.128/25 10.1.2.1 eth2",
                         "0.0.0.0/0 9.9.9.9 eth0"};
  const size_t n = sizeof lines / sizeof lines[0];
  const char *probes[] = {"10.1.2.200", "10.1.2.5", "10.1.9.9", "10.9.9.9", "8.8.8.8"};
  const uint8_t want[] = {25, 24, 16, 8, 0};

  fwd_table_t *fwd = table_create();
  fwd_table_t *rev = table_create();
  for (size_t i = 0; i < n; i++)
  {
    route_t a, b;
    TEST_ASSERT_TRUE(route_parse(lines[i], &a));
    TEST_ASSERT_TRUE(route_parse(lines[n - 1 - i], &b));
    TEST_ASSERT_TRUE(table_add(fwd, &a));
    TEST_ASSERT_TRUE(table_add(rev, &b));
  }
  for (size_t i = 0; i < sizeof probes / sizeof probes[0]; i++)
  {
    const route_t *a = table_lookup(fwd, ip(probes[i]));
    const route_t *b = table_lookup(rev, ip(probes[i]));
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_NOT_NULL(b);
    TEST_ASSERT_EQUAL_UINT8(want[i], a->dest.prefix);
    TEST_ASSERT_EQUAL_UINT8(want[i], b->dest.prefix);
    TEST_ASSERT_EQUAL_HEX32(a->dest.addr, b->dest.addr);
  }
  table_destroy(fwd);
  table_destroy(rev);
}

void test_lookup_without_default_route(void)
{
  fwd_table_t *t = table_create();
  TEST_ASSERT_NULL(table_lookup(t, ip("1.2.3.4")));
  TEST_ASSERT_TRUE(load_text(t, "10.0.0.0/8 direct eth0\n1.2.3.4/32 direct eth1\n", NULL));
  TEST_ASSERT_NULL(table_lookup(t, ip("8.8.8.8")));
  TEST_ASSERT_NULL(table_lookup(t, ip("1.2.3.5")));
  TEST_ASSERT_NULL(table_lookup(t, 0));
  TEST_ASSERT_NULL(table_lookup(t, 0xFFFFFFFF));
  TEST_ASSERT_EQUAL_STRING("eth1", table_lookup(t, ip("1.2.3.4"))->dev);
  TEST_ASSERT_EQUAL_STRING("eth0", table_lookup(t, ip("10.255.255.255"))->dev);
  table_destroy(t);
}

void test_default_route_matches_extremes(void)
{
  fwd_table_t *t = table_create();
  route_t r = make_route("0.0.0.0/0", "1.1.1.1", "eth0");
  TEST_ASSERT_TRUE(table_add(t, &r));
  TEST_ASSERT_NOT_NULL(table_lookup(t, 0));
  TEST_ASSERT_NOT_NULL(table_lookup(t, 0xFFFFFFFF));
  table_destroy(t);
}

void test_table_load_bad_line_in_middle(void)
{
  fwd_table_t *t = table_create();
  size_t bad = 0;
  const char *text = "# header\n"
                     "\n"
                     "10.0.0.0/8 10.1.0.1 eth1\n"
                     "10.1.0.0/16 direct eth1   # fine\n"
                     "10.1.2.0/24 direct\n"
                     "192.168.0.0/16 direct eth0\n";
  TEST_ASSERT_FALSE(load_text(t, text, &bad));
  TEST_ASSERT_EQUAL_UINT(5, bad);
  TEST_ASSERT_EQUAL_UINT(2, table_count(t));
  TEST_ASSERT_NULL(table_lookup(t, ip("192.168.1.1")));
  table_destroy(t);
}

void test_table_load_duplicate_line_is_bad(void)
{
  fwd_table_t *t = table_create();
  size_t bad = 0;
  TEST_ASSERT_FALSE(load_text(t, "10.0.0.0/8 direct eth0\n10.0.0.0/8 direct eth1\n", &bad));
  TEST_ASSERT_EQUAL_UINT(2, bad);
  TEST_ASSERT_EQUAL_UINT(1, table_count(t));
  table_destroy(t);
}

void test_table_load_edge_cases(void)
{
  fwd_table_t *t = table_create();
  size_t bad = 99;
  /* Empty file. */
  TEST_ASSERT_TRUE(load_text(t, "", &bad));
  TEST_ASSERT_EQUAL_UINT(0, bad);
  /* Only comments and blanks, no trailing newline on the last route. */
  TEST_ASSERT_TRUE(load_text(t, "# a\n   \t\n#b\n10.0.0.0/8 direct eth0", NULL));
  TEST_ASSERT_EQUAL_UINT(1, table_count(t));
  /* A bad first line is line 1, and a NULL bad_line is allowed. */
  TEST_ASSERT_FALSE(load_text(t, "junk\n", &bad));
  TEST_ASSERT_EQUAL_UINT(1, bad);
  TEST_ASSERT_FALSE(load_text(t, "junk\n", NULL));
  table_destroy(t);
}

void test_table_load_bad_arguments(void)
{
  size_t bad = 99;
  fwd_table_t *t = table_create();
  FILE *f = tmpfile();
  TEST_ASSERT_FALSE(table_load(NULL, f, &bad));
  TEST_ASSERT_EQUAL_UINT(0, bad);
  bad = 99;
  TEST_ASSERT_FALSE(table_load(t, NULL, &bad));
  TEST_ASSERT_EQUAL_UINT(0, bad);
  TEST_ASSERT_FALSE(table_load(t, NULL, NULL));
  fclose(f);

  /* A stream that can not be read. */
  FILE *w = fopen("/dev/null", "w");
  TEST_ASSERT_NOT_NULL(w);
  bad = 99;
  TEST_ASSERT_FALSE(table_load(t, w, &bad));
  TEST_ASSERT_EQUAL_UINT(0, bad);
  fclose(w);
  table_destroy(t);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_valid);
  RUN_TEST(test_ip_parse_rejects_malformed);
  RUN_TEST(test_ip_format);
  RUN_TEST(test_cidr_parse_valid);
  RUN_TEST(test_cidr_parse_rejects_malformed);
  RUN_TEST(test_cidr_format);
  RUN_TEST(test_cidr_mask);
  RUN_TEST(test_network_and_broadcast);
  RUN_TEST(test_first_and_last_host);
  RUN_TEST(test_host_count);
  RUN_TEST(test_contains);
  RUN_TEST(test_is_network);
  RUN_TEST(test_subnet);
  RUN_TEST(test_subnet_failures);
  RUN_TEST(test_route_parse_valid);
  RUN_TEST(test_route_parse_rejects_malformed);
  RUN_TEST(test_table_create_destroy);
  RUN_TEST(test_table_add);
  RUN_TEST(test_table_grows);
  RUN_TEST(test_table_load_example_and_lookup);
  RUN_TEST(test_lookup_independent_of_order);
  RUN_TEST(test_lookup_without_default_route);
  RUN_TEST(test_default_route_matches_extremes);
  RUN_TEST(test_table_load_bad_line_in_middle);
  RUN_TEST(test_table_load_duplicate_line_is_bad);
  RUN_TEST(test_table_load_edge_cases);
  RUN_TEST(test_table_load_bad_arguments);
  return UNITY_END();
}
