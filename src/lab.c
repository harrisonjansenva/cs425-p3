#include "lab.h"
#include <stdlib.h>
#include <string.h>

#define WHITESPACE " \t\r\n"

/* ------------------------------------------------------------------------
 * Task 1 - Address parsing and formatting
 * --------------------------------------------------------------------- */

static bool is_digit(char c)
{
  return c >= '0' && c <= '9';
}

/**
 * Parse a run of decimal digits with no leading zero (a lone "0" is fine) and a
 * value no larger than max. Returns the first character after the digits, or
 * NULL if there is no number or it is not acceptable.
 */
static const char *parse_number(const char *s, uint32_t max, uint32_t *value)
{
  if (!is_digit(*s))
  {
    return NULL;
  }
  if (s[0] == '0' && is_digit(s[1]))
  {
    return NULL;
  }

  uint32_t v = 0;
  while (is_digit(*s))
  {
    v = v * 10 + (uint32_t)(*s - '0');
    if (v > max)
    {
      return NULL;
    }
    s++;
  }
  *value = v;
  return s;
}

/** Parse a dotted quad at the start of s; returns the character after it or NULL. */
static const char *parse_quad(const char *s, uint32_t *addr)
{
  uint32_t result = 0;
  for (int i = 0; i < 4; i++)
  {
    uint32_t octet;
    s = parse_number(s, 255, &octet);
    if (s == NULL)
    {
      return NULL;
    }
    result = (result << 8) | octet;
    if (i < 3)
    {
      if (*s != '.')
      {
        return NULL;
      }
      s++;
    }
  }
  *addr = result;
  return s;
}

bool ip_parse(const char *text, uint32_t *addr)
{
  if (text == NULL)
  {
    return false;
  }
  uint32_t value;
  const char *end = parse_quad(text, &value);
  if (end == NULL || *end != '\0')
  {
    return false;
  }
  if (addr != NULL)
  {
    *addr = value;
  }
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
  snprintf(out, IP_STR_LEN, "%u.%u.%u.%u", (addr >> 24) & 0xFFu, (addr >> 16) & 0xFFu,
           (addr >> 8) & 0xFFu, addr & 0xFFu);
}

bool cidr_parse(const char *text, cidr_t *block)
{
  if (text == NULL)
  {
    return false;
  }
  uint32_t addr;
  const char *end = parse_quad(text, &addr);
  if (end == NULL || *end != '/')
  {
    return false;
  }
  uint32_t prefix;
  end = parse_number(end + 1, 32, &prefix);
  if (end == NULL || *end != '\0')
  {
    return false;
  }
  if (block != NULL)
  {
    block->addr = addr;
    block->prefix = (uint8_t)prefix;
  }
  return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN])
{
  char ip[IP_STR_LEN];
  ip_format(block.addr, ip);
  snprintf(out, CIDR_STR_LEN, "%s/%u", ip, block.prefix > 32 ? 32u : (unsigned)block.prefix);
}

/* ------------------------------------------------------------------------
 * Task 2 - Subnet arithmetic
 * --------------------------------------------------------------------- */

uint32_t cidr_mask(uint8_t prefix)
{
  if (prefix == 0)
  {
    return 0;
  }
  if (prefix > 32)
  {
    prefix = 32;
  }
  return 0xFFFFFFFFu << (32 - prefix);
}

uint32_t cidr_network(cidr_t block)
{
  return block.addr & cidr_mask(block.prefix);
}

uint32_t cidr_broadcast(cidr_t block)
{
  return block.addr | ~cidr_mask(block.prefix);
}

uint32_t cidr_first_host(cidr_t block)
{
  uint32_t network = cidr_network(block);
  return block.prefix >= 31 ? network : network + 1;
}

uint32_t cidr_last_host(cidr_t block)
{
  uint32_t broadcast = cidr_broadcast(block);
  return block.prefix >= 31 ? broadcast : broadcast - 1;
}

uint64_t cidr_host_count(cidr_t block)
{
  if (block.prefix >= 32)
  {
    return 1;
  }
  if (block.prefix == 31)
  {
    return 2;
  }
  return (UINT64_C(1) << (32 - block.prefix)) - 2;
}

bool cidr_contains(cidr_t block, uint32_t addr)
{
  uint32_t mask = cidr_mask(block.prefix);
  return (addr & mask) == (block.addr & mask);
}

bool cidr_is_network(cidr_t block)
{
  return block.addr == cidr_network(block);
}

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out)
{
  if (out == NULL || !cidr_is_network(block) || n == 0 || (n & (n - 1)) != 0)
  {
    return false;
  }

  uint32_t bits = 0;
  while ((UINT32_C(1) << bits) < n)
  {
    bits++;
  }

  uint32_t prefix = block.prefix > 32 ? 32 : block.prefix;
  uint32_t new_prefix = prefix + bits;
  if (new_prefix > 32 || i >= n)
  {
    return false;
  }

  uint64_t offset = (uint64_t)i << (32 - new_prefix);
  out->addr = (uint32_t)(cidr_network(block) + offset);
  out->prefix = (uint8_t)new_prefix;
  return true;
}

/* ------------------------------------------------------------------------
 * Task 3 - Longest prefix match
 * --------------------------------------------------------------------- */

/** Longest field route_parse() needs to look at, with room for its '\0'. */
#define FIELD_LEN 32

/** Copy the next whitespace separated field into buf; false if none or too long. */
static bool next_field(const char **p, char buf[FIELD_LEN])
{
  const char *s = *p + strspn(*p, WHITESPACE);
  size_t len = strcspn(s, WHITESPACE);
  if (len == 0 || len >= FIELD_LEN)
  {
    return false;
  }
  memcpy(buf, s, len);
  buf[len] = '\0';
  *p = s + len;
  return true;
}

bool route_parse(const char *line, route_t *route)
{
  if (line == NULL)
  {
    return false;
  }

  char dest[FIELD_LEN];
  char gateway[FIELD_LEN];
  char dev[FIELD_LEN];
  const char *p = line;
  if (!next_field(&p, dest) || !next_field(&p, gateway) || !next_field(&p, dev))
  {
    return false;
  }
  if (p[strspn(p, WHITESPACE)] != '\0' || strlen(dev) >= DEV_NAME_LEN)
  {
    return false;
  }

  route_t result = {0};
  if (strcmp(dest, "default") == 0)
  {
    result.dest.addr = 0;
    result.dest.prefix = 0;
  }
  else if (!cidr_parse(dest, &result.dest) || !cidr_is_network(result.dest))
  {
    return false;
  }

  if (strcmp(gateway, "direct") == 0)
  {
    result.gateway = 0;
  }
  else if (!ip_parse(gateway, &result.gateway))
  {
    return false;
  }

  strcpy(result.dev, dev);
  if (route != NULL)
  {
    *route = result;
  }
  return true;
}

struct fwd_table
{
  route_t *routes;
  size_t count;
  size_t capacity;
};

fwd_table_t *table_create(void)
{
  return calloc(1, sizeof(fwd_table_t));
}

void table_destroy(fwd_table_t *table)
{
  if (table == NULL)
  {
    return;
  }
  free(table->routes);
  free(table);
}

size_t table_count(const fwd_table_t *table)
{
  return table == NULL ? 0 : table->count;
}

bool table_add(fwd_table_t *table, const route_t *route)
{
  if (table == NULL || route == NULL || !cidr_is_network(route->dest))
  {
    return false;
  }
  for (size_t i = 0; i < table->count; i++)
  {
    if (table->routes[i].dest.addr == route->dest.addr &&
        table->routes[i].dest.prefix == route->dest.prefix)
    {
      return false;
    }
  }

  if (table->count == table->capacity)
  {
    size_t capacity = table->capacity == 0 ? 4 : table->capacity * 2;
    route_t *grown = realloc(table->routes, capacity * sizeof(route_t));
    if (grown == NULL) // GCOVR_EXCL_START
    {
      return false;
    } // GCOVR_EXCL_STOP
    table->routes = grown;
    table->capacity = capacity;
  }

  table->routes[table->count++] = *route;
  return true;
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line)
{
  if (bad_line != NULL)
  {
    *bad_line = 0;
  }
  if (table == NULL || in == NULL)
  {
    return false;
  }

  char *line = NULL;
  size_t cap = 0;
  size_t number = 0;
  bool ok = true;

  while (getline(&line, &cap, in) != -1)
  {
    number++;
    char *comment = strchr(line, '#');
    if (comment != NULL)
    {
      *comment = '\0';
    }
    if (line[strspn(line, WHITESPACE)] == '\0')
    {
      continue;
    }

    route_t route;
    if (!route_parse(line, &route) || !table_add(table, &route))
    {
      if (bad_line != NULL)
      {
        *bad_line = number;
      }
      ok = false;
      break;
    }
  }

  free(line);
  return ok && !ferror(in);
}

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest)
{
  if (table == NULL)
  {
    return NULL;
  }
  const route_t *best = NULL;
  for (size_t i = 0; i < table->count; i++)
  {
    const route_t *r = &table->routes[i];
    if (cidr_contains(r->dest, dest) && (best == NULL || r->dest.prefix > best->dest.prefix))
    {
      best = r;
    }
  }
  return best;
}
