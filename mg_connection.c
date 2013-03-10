#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#define ERRNO errno

#include "mongoose.h"

#ifdef DEBUG_TRACE
#undef DEBUG_TRACE
#define DEBUG_TRACE(x)
#else
#if defined(DEBUG)
#define DEBUG_TRACE(x) do { \
  flockfile(stdout); \
  printf("*** %lu.%p.%s.%d: ", \
         (unsigned long) time(NULL), (void *) pthread_self(), \
         __func__, __LINE__); \
  printf x; \
  putchar('\n'); \
  fflush(stdout); \
  funlockfile(stdout); \
} while (0)
#else
#define DEBUG_TRACE(x)
#endif // DEBUG
#endif // DEBUG_TRACE

// Authorize against the opened passwords file. Return 1 if authorized.
static int authorize(struct mg_connection *conn, struct file *filep) {
  struct ah ah;
  char line[256], f_user[256], ha1[256], f_domain[256], buf[MG_BUF_LEN], *p;

  if (!parse_auth_header(conn, buf, sizeof(buf), &ah)) {
    return 0;
  }

  // Loop over passwords file
  p = (char *) filep->membuf;
  while (mg_fgets(line, sizeof(line), filep, &p) != NULL) {
    if (sscanf(line, "%[^:]:%[^:]:%s", f_user, f_domain, ha1) != 3) {
      continue;
    }

    if (!strcmp(ah.user, f_user) &&
        !strcmp(conn->ctx->config[AUTHENTICATION_DOMAIN], f_domain))
      return check_password(conn->request_info.request_method, ha1, ah.uri,
                            ah.nonce, ah.nc, ah.cnonce, ah.qop, ah.response);
  }

  return 0;
}

// Use the global passwords file, if specified by auth_gpass option,
// or search for .htpasswd in the requested directory.
static void open_auth_file(struct mg_connection *conn, const char *path,
                           struct file *filep) {
  char name[PATH_MAX];
  const char *p, *e, *gpass = conn->ctx->config[GLOBAL_PASSWORDS_FILE];

  if (gpass != NULL) {
    // Use global passwords file
    if (!mg_fopen(conn, gpass, "r", filep)) {
      cry(conn, "fopen(%s): %s", gpass, strerror(ERRNO));
    }
  } else if (mg_stat(conn, path, filep) && filep->is_directory) {
    mg_snprintf(conn, name, sizeof(name), "%s%c%s",
                path, '/', PASSWORDS_FILE_NAME);
    mg_fopen(conn, name, "r", filep);
  } else {
     // Try to find .htpasswd in requested directory.
    for (p = path, e = p + strlen(p) - 1; e > p; e--)
      if (e[0] == '/')
        break;
    mg_snprintf(conn, name, sizeof(name), "%.*s%c%s",
                (int) (e - p), p, '/', PASSWORDS_FILE_NAME);
    mg_fopen(conn, name, "r", filep);
  }
}

// Return 1 if request is authorised, 0 otherwise.
static int check_authorization(struct mg_connection *conn, const char *path) {
  char fname[PATH_MAX];
  struct vec uri_vec, filename_vec;
  const char *list;
  struct file file = STRUCT_FILE_INITIALIZER;
  int authorized = 1;

  list = conn->ctx->config[PROTECT_URI];
  while ((list = next_option(list, &uri_vec, &filename_vec)) != NULL) {
    if (!memcmp(conn->request_info.uri, uri_vec.ptr, uri_vec.len)) {
      mg_snprintf(conn, fname, sizeof(fname), "%.*s",
                  (int) filename_vec.len, filename_vec.ptr);
      if (!mg_fopen(conn, fname, "r", &file)) {
        cry(conn, "%s: cannot open %s: %s", __func__, fname, strerror(errno));
      }
      break;
    }
  }

  if (!is_file_opened(&file)) {
    open_auth_file(conn, path, &file);
  }

  if (is_file_opened(&file)) {
    authorized = authorize(conn, &file);
    mg_fclose(&file);
  }

  return authorized;
}

static int is_authorized_for_put(struct mg_connection *conn) {
  struct file file = STRUCT_FILE_INITIALIZER;
  const char *passfile = conn->ctx->config[PUT_DELETE_PASSWORDS_FILE];
  int ret = 0;

  if (passfile != NULL && mg_fopen(conn, passfile, "r", &file)) {
    ret = authorize(conn, &file);
    mg_fclose(&file);
  }

  return ret;
}


static void send_authorization_request(struct mg_connection *conn) {
  conn->status_code = 401;
  mg_printf(conn,
            "HTTP/1.1 401 Unauthorized\r\n"
            "Content-Length: 0\r\n"
            "WWW-Authenticate: Digest qop=\"auth\", "
            "realm=\"%s\", nonce=\"%lu\"\r\n\r\n",
            conn->ctx->config[AUTHENTICATION_DOMAIN],
            (unsigned long) time(NULL));
}

static void handle_directory_request(struct mg_connection *conn,
                                     const char *dir) {
  int i, sort_direction;
  struct dir_scan_data data = { NULL, 0, 128 };

  if (!scan_directory(conn, dir, &data, dir_scan_callback)) {
    send_http_error(conn, 500, "Cannot open directory",
                    "Error: opendir(%s): %s", dir, strerror(ERRNO));
    return;
  }

  sort_direction = conn->request_info.query_string != NULL &&
    conn->request_info.query_string[1] == 'd' ? 'a' : 'd';

  conn->must_close = 1;
  mg_printf(conn, "%s",
            "HTTP/1.1 200 OK\r\n"
            "Connection: close\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n");

  conn->num_bytes_sent += mg_printf(conn,
      "<html><head><title>Index of %s</title>"
      "<style>th {text-align: left;}</style></head>"
      "<body><h1>Index of %s</h1><pre><table cellpadding=\"0\">"
      "<tr><th><a href=\"?n%c\">Name</a></th>"
      "<th><a href=\"?d%c\">Modified</a></th>"
      "<th><a href=\"?s%c\">Size</a></th></tr>"
      "<tr><td colspan=\"3\"><hr></td></tr>",
      conn->request_info.uri, conn->request_info.uri,
      sort_direction, sort_direction, sort_direction);

  // Print first entry - link to a parent directory
  conn->num_bytes_sent += mg_printf(conn,
      "<tr><td><a href=\"%s%s\">%s</a></td>"
      "<td>&nbsp;%s</td><td>&nbsp;&nbsp;%s</td></tr>\n",
      conn->request_info.uri, "..", "Parent directory", "-", "-");

  // Sort and print directory entries
  qsort(data.entries, (size_t) data.num_entries, sizeof(data.entries[0]),
        compare_dir_entries);
  for (i = 0; i < data.num_entries; i++) {
    print_dir_entry(&data.entries[i]);
    free(data.entries[i].file_name);
  }
  free(data.entries);

  conn->num_bytes_sent += mg_printf(conn, "%s", "</table></body></html>");
  conn->status_code = 200;
}


// This is the heart of the Mongoose's logic.
// This function is called when the request is read, parsed and validated,
// and Mongoose must decide what action to take: serve a file, or
// a directory, or call embedded function, etcetera.
static void handle_request(struct mg_connection *conn) {
  struct mg_request_info *ri = &conn->request_info;
  char path[PATH_MAX];
  int uri_len, ssl_index;
  struct file file = STRUCT_FILE_INITIALIZER;

  if ((conn->request_info.query_string = strchr(ri->uri, '?')) != NULL) {
    * ((char *) conn->request_info.query_string++) = '\0';
  }
  uri_len = (int) strlen(ri->uri);
  url_decode(ri->uri, uri_len, (char *) ri->uri, uri_len + 1, 0);
  remove_double_dots_and_double_slashes((char *) ri->uri);
  convert_uri_to_file_name(conn, path, sizeof(path), &file);
  conn->throttle = set_throttle(conn->ctx->config[THROTTLE],
                                get_remote_ip(conn), ri->uri);

  DEBUG_TRACE(("%s", ri->uri));
  // Perform redirect and auth checks before calling begin_request() handler.
  // Otherwise, begin_request() would need to perform auth checks and redirects.
  if (!conn->client.is_ssl && conn->client.ssl_redir &&
      (ssl_index = get_first_ssl_listener_index(conn->ctx)) > -1) {
    redirect_to_https_port(conn, ssl_index);
  } else if (!is_put_or_delete_request(conn) &&
             !check_authorization(conn, path)) {
    send_authorization_request(conn);
  } else if (conn->ctx->callbacks.begin_request != NULL &&
      conn->ctx->callbacks.begin_request(conn)) {
    // Do nothing, callback has served the request
/* #if defined(USE_WEBSOCKET) */
/*   } else if (is_websocket_request(conn)) { */
/*     handle_websocket_request(conn); */
/* #endif */
  } else if (!strcmp(ri->request_method, "OPTIONS")) {
    send_options(conn);
  } else if (conn->ctx->config[DOCUMENT_ROOT] == NULL) {
    send_http_error(conn, 404, "Not Found", "Not Found");
  } else if (is_put_or_delete_request(conn) &&
             (conn->ctx->config[PUT_DELETE_PASSWORDS_FILE] == NULL ||
              is_authorized_for_put(conn) != 1)) {
    send_authorization_request(conn);
  } else if (!strcmp(ri->request_method, "PUT")) {
    put_file(conn, path);
  } else if (!strcmp(ri->request_method, "DELETE")) {
    if (remove(path) == 0) {
      send_http_error(conn, 200, "OK", "%s", "");
    } else {
      send_http_error(conn, 500, http_500_error, "remove(%s): %s", path,
                      strerror(ERRNO));
    }
  } else if ((file.membuf == NULL && file.modification_time == (time_t) 0) ||
             must_hide_file(conn, path)) {
    send_http_error(conn, 404, "Not Found", "%s", "File not found");
  } else if (file.is_directory && ri->uri[uri_len - 1] != '/') {
    mg_printf(conn, "HTTP/1.1 301 Moved Permanently\r\n"
              "Location: %s/\r\n\r\n", ri->uri);
  } else if (!strcmp(ri->request_method, "PROPFIND")) {
    handle_propfind(conn, path, &file);
  } else if (file.is_directory &&
             !substitute_index_file(conn, path, sizeof(path), &file)) {
    if (!mg_strcasecmp(conn->ctx->config[ENABLE_DIRECTORY_LISTING], "yes")) {
      handle_directory_request(conn, path);
    } else {
      send_http_error(conn, 403, "Directory Listing Denied",
          "Directory listing denied");
    }
#if !defined(NO_CGI)
  } else if (match_prefix(conn->ctx->config[CGI_EXTENSIONS],
                          strlen(conn->ctx->config[CGI_EXTENSIONS]),
                          path) > 0) {
    if (strcmp(ri->request_method, "POST") &&
        strcmp(ri->request_method, "HEAD") &&
        strcmp(ri->request_method, "GET")) {
      send_http_error(conn, 501, "Not Implemented",
                      "Method %s is not implemented", ri->request_method);
    } else {
      handle_cgi_request(conn, path);
    }
#endif // !NO_CGI
  } else if (match_prefix(conn->ctx->config[SSI_EXTENSIONS],
                          strlen(conn->ctx->config[SSI_EXTENSIONS]),
                          path) > 0) {
    handle_ssi_file_request(conn, path);
  } else if (is_not_modified(conn, &file)) {
    send_http_error(conn, 304, "Not Modified", "%s", "");
  } else {
    handle_file_request(conn, path, &file);
  }
}

static int getreq(struct mg_connection *conn, char *ebuf, size_t ebuf_len) {
  const char *cl;

  ebuf[0] = '\0';
  reset_per_request_attributes(conn);
  conn->request_len = read_request(NULL, conn, conn->buf, conn->buf_size,
                                   &conn->data_len);
  assert(conn->request_len < 0 || conn->data_len >= conn->request_len);

  if (conn->request_len == 0 && conn->data_len == conn->buf_size) {
    snprintf(ebuf, ebuf_len, "%s", "Request Too Large");
  } else if (conn->request_len <= 0) {
    snprintf(ebuf, ebuf_len, "%s", "Client closed connection");
  } else if (parse_http_message(conn->buf, conn->buf_size,
                                &conn->request_info) <= 0) {
    snprintf(ebuf, ebuf_len, "Bad request: [%.*s]", conn->data_len, conn->buf);
  } else {
    // Request is valid
    if ((cl = get_header(&conn->request_info, "Content-Length")) != NULL) {
      conn->content_len = strtoll(cl, NULL, 10);
    } else if (!mg_strcasecmp(conn->request_info.request_method, "POST") ||
               !mg_strcasecmp(conn->request_info.request_method, "PUT")) {
      conn->content_len = -1;
    } else {
      conn->content_len = 0;
    }
    conn->birth_time = time(NULL);
  }
  return ebuf[0] == '\0';
}

void process_new_connection(struct mg_connection *conn) {
  struct mg_request_info *ri = &conn->request_info;
  int keep_alive_enabled, keep_alive, discard_len;
  char ebuf[100];

  keep_alive_enabled = !strcmp(conn->ctx->config[ENABLE_KEEP_ALIVE], "yes");
  keep_alive = 0;

  // Important: on new connection, reset the receiving buffer. Credit goes
  // to crule42.
  conn->data_len = 0;
  do {
    if (!getreq(conn, ebuf, sizeof(ebuf))) {
      send_http_error(conn, 500, "Server Error", "%s", ebuf);
      conn->must_close = 1;
    } else if (!is_valid_uri(conn->request_info.uri)) {
      snprintf(ebuf, sizeof(ebuf), "Invalid URI: [%s]", ri->uri);
      send_http_error(conn, 400, "Bad Request", "%s", ebuf);
    } else if (strcmp(ri->http_version, "1.0") &&
               strcmp(ri->http_version, "1.1")) {
      snprintf(ebuf, sizeof(ebuf), "Bad HTTP version: [%s]", ri->http_version);
      send_http_error(conn, 505, "Bad HTTP version", "%s", ebuf);
    }

    if (ebuf[0] == '\0') {
      handle_request(conn);
      if (conn->ctx->callbacks.end_request != NULL) {
        conn->ctx->callbacks.end_request(conn, conn->status_code);
      }
      log_access(conn);
    }
    if (ri->remote_user != NULL) {
      free((void *) ri->remote_user);
    }

    // NOTE(lsm): order is important here. should_keep_alive() call
    // is using parsed request, which will be invalid after memmove's below.
    // Therefore, memorize should_keep_alive() result now for later use
    // in loop exit condition.
    keep_alive = conn->ctx->stop_flag == 0 && keep_alive_enabled &&
      conn->content_len >= 0 && should_keep_alive(conn);

    // Discard all buffered data for this request
    discard_len = conn->content_len >= 0 && conn->request_len > 0 &&
      conn->request_len + conn->content_len < (int64_t) conn->data_len ?
      (int) (conn->request_len + conn->content_len) : conn->data_len;
    assert(discard_len >= 0);
    memmove(conn->buf, conn->buf + discard_len, conn->data_len - discard_len);
    conn->data_len -= discard_len;
    assert(conn->data_len >= 0);
    assert(conn->data_len <= conn->buf_size);
  } while (keep_alive);
}
