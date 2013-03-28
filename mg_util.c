#include "mongoose.h"
#include <stdarg.h>

void mg_printf_inc(struct mg_connection *conn, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  conn->num_bytes_sent += mg_vprintf(conn, fmt, ap);
}

struct pw_ent *parse_password_line(char *line) {
  struct pw_ent *pw;
  char f_user[256], f_domain[256], ha1[256];

  if (scanf(line, "%[^:]:%[^:]:%s", f_user, f_domain, ha1) != 3) {
    return NULL;
  }

  pw = malloc(sizeof(*pw));
  pw->user   = strndup(f_user, 256);
  pw->domain = strndup(f_domain, 256);
  pw->ha1    = malloc(sizeof(ha1));
  memcpy(pw->ha1, ha1, 256);

  return pw;
}

void print_dir_entries(struct dir_scan_data *data)
{
  int i;

  // Sort and print directory entries
  qsort(data->entries, (size_t) data->num_entries, sizeof(data->entries[0]),
        compare_dir_entries);
  for (i = 0; i < data->num_entries; i++) {
    print_dir_entry(&data->entries[i]);
    free(data->entries[i].file_name);
  }
}

