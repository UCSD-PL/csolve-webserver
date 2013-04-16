#include "mongoose.h"
#include <stdarg.h>
#include <errno.h>

void mg_printf_inc(struct mg_connection *conn, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  conn->num_bytes_sent += mg_vprintf(conn, fmt, ap);
}

void initialize_file(struct file *f)
{
  f->is_directory = 0;
  f->modification_time = 0;
  f->size = 0;
  f->fp = NULL;
  f->membuf = NULL;
}

struct file *
mg_fopena(struct mg_connection *c, const char *path, const char *mode) {
  struct file *f = malloc(sizeof(*f));
  initialize_file(f);
  if (!mg_fopen(c,path,mode,f)) {
    free(f);
    f = NULL;
  }
  return f;
}

struct file *
open_auth_file_aux(struct mg_connection *conn, const char *path) {
  struct file *filep = NULL;
  char *e;
  char name[PATH_MAX];

  filep = malloc(sizeof(*filep));
  initialize_file(filep);

  if (mg_stat(conn, path, filep) && filep->is_directory)
  {
    mg_snprintf(conn, name, sizeof(name), "%s%c%s",
                path, '/', PASSWORDS_FILE_NAME);
    mg_fopen(conn, name, "r", filep);
  }
  else
  {
    e = strrchr(path, '/');
    mg_snprintf(conn, name, sizeof(name), "%.*s%c%s",
                  (ptrdiff_t)e - (ptrdiff_t)path, path, '/', PASSWORDS_FILE_NAME);
    mg_fopen(conn, name, "r", filep);
  }

  if (!is_file_opened(filep)) {
    free(filep);//leak
    filep = NULL;
  }
  return filep;
}

struct pw_ent *parse_password_line(char *line) {
  struct pw_ent *pw;
  char f_user[256], f_domain[256], ha1[256];

  if (sscanf(line, "%[^:]:%[^:]:%s", f_user, f_domain, ha1) != 3) {
    return NULL;
  }

  pw = malloc(sizeof(*pw));
  pw->user   = strndup(f_user, 256);
  pw->domain = strndup(f_domain, 256);
  pw->ha1    = malloc(sizeof(ha1));
  memcpy(pw->ha1, ha1, 256);

  return pw;
}

void print_dir_entries(struct dir_scan_data *data) {
  int i;

  // Sort and print directory entries
  qsort(data->entries, (size_t) data->num_entries, sizeof(data->entries[0]),
        compare_dir_entries);
  for (i = 0; i < data->num_entries; i++) {
    print_dir_entry(&data->entries[i]);
    free(data->entries[i].file_name);
  }
}

char *mg_protect_uri_fname(struct mg_connection *conn) {
  char *fname = NULL;
  struct vec uri_vec, filename_vec;
  const char *list;
  struct file *file = malloc(sizeof(*file));
  initialize_file(file);

  list = conn->ctx->config[PROTECT_URI];

  while (list && (list = next_option(list, &uri_vec, &filename_vec)) != NULL) {
#warning "CSOLVE: Possible bug?"
    /* ABAKST Possible bug here? memcmp vs strcmp? */
    printf("(%s) =? (%s)\n", conn->request_info.uri, uri_vec.ptr);
       if (uri_vec.ptr && !memcmp(conn->request_info.uri, uri_vec.ptr, uri_vec.len)) {
    
    /* if (uri_vec.ptr && !strcmp(conn->request_info.uri, uri_vec.ptr)) { */
      fname = malloc(PATH_MAX);
      mg_snprintf(conn, fname, PATH_MAX, "%.*s",
                  (int) filename_vec.len, filename_vec.ptr);
      if (!mg_fopen(conn, fname, "r", file)) {
        cry(conn, "%s: cannot open %s: %s", __func__, fname, strerror(errno));
      }
      break;
    }
  }

  return fname;
}

int REF((V != 0) => ? AUTHORIZED([CONN([conn])]))
  mg_check_no_auth(struct mg_connection FINAL *conn, char *path)
{
  return 1;
}
