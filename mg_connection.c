#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#define ERRNO errno

#include "mongoose.h"
#include "mg_auth.h"
#include "mg_util.h"
#include "mongoose-policy.h"

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

/* void */
/* handle_directory_request(struct mg_connection INST(CTX_CFG,CTX_CFG)* OK M REF(?AUTHORIZED([CONN([V])])) conn, */
/*                          const char NULLTERMSTR *LOC(CTX_CFG) STRINGPTR dir) */
/* { */
/*   int i, sort_direction; */
/*   struct dir_scan_data data = { NULL, 0, 128 }; */

/*   if (!scan_directory(conn, dir, &data, dir_scan_callback)) { */
/*     send_http_error(conn, 500, "Cannot open directory", */
/*                     "Error: opendir"); */
/*                     /\* "Error: opendir(%s): %s", dir, strerror(ERRNO)); *\/ */
/*     return; */
/*   } */

/*   sort_direction = conn->request_info.query_string != NULL && */
/*     conn->request_info.query_string[0] && */
/*     conn->request_info.query_string[1] == 'd' ? 'a' : 'd'; */

/*   conn->must_close = 1; */
/*   mg_printf(conn, "%s", */
/*             "HTTP/1.1 200 OK\r\n" */
/*             "Connection: close\r\n" */
/*             "Content-Type: text/html; charset=utf-8\r\n\r\n"); */

/*   mg_printf_inc(conn, */
/*       "<html><head><title>Index of %s</title>" */
/*       "<style>th {text-align: left;}</style></head>" */
/*       "<body><h1>Index of %s</h1><pre><table cellpadding=\"0\">" */
/*       "<tr><th><a href=\"?n%c\">Name</a></th>" */
/*       "<th><a href=\"?d%c\">Modified</a></th>" */
/*       "<th><a href=\"?s%c\">Size</a></th></tr>" */
/*                                     "<tr><td colspan=\"3\"><hr></td></tr>", */
/*       conn->request_info.uri, conn->request_info.uri, */
/*       sort_direction, sort_direction, sort_direction); */

/*   // Print first entry - link to a parent directory */
/*   mg_printf_inc(conn, */
/*       "<tr><td><a href=\"%s%s\">%s</a></td>" */
/*       "<td>&nbsp;%s</td><td>&nbsp;&nbsp;%s</td></tr>\n", */
/*       conn->request_info.uri, "..", "Parent directory", "-", "-"); */

/*   print_dir_entries(&data); */
/*   if (data.entries) { */
/*     free(data.entries); */
/*   } */

/*   mg_printf_inc(conn, "%s", "</table></body></html>"); */
/*   conn->status_code = 200; */
/* } */


void
prepare_request(struct mg_connection_pre *conn)
{
  struct mg_request_info_pre *ri = &conn->request_info;
  char *query_string = NULL;
  char *uri          = NULL;
  int uri_len;

  if ((uri = ri->uri) == NULL)
    return;

  if ((query_string = strchr(ri->uri, '?')) != NULL)
  {
    if (*query_string) {
      * ((char *) query_string++) = '\0';
    } else {
      query_string = NULL;
    }
  }
  conn->request_info.query_string = query_string;
  uri_len = (int) strlen(uri);
  url_decode(uri, uri_len, (char *) uri, uri_len + 1, 0);
  remove_double_dots_and_double_slashes((char *) uri);
  conn->throttle = set_throttle(conn->ctx->config[THROTTLE],
                                get_remote_ip(freeze_conn(conn)),
                                uri);
  DEBUG_TRACE(("%s", ri->uri));

}
// This is the heart of the Mongoose's logic.
// This function is called when the request is read, parsed and validated,
// and Mongoose must decide what action to take: serve a file, or
// a directory, or call embedded function, etcetera.
void
handle_request(struct mg_connection_pre * OK OK_URI OK_CONN M conn)
  CHECK_TYPE
{
  struct mg_request_info *ri;// = &conn->request_info;
  char *path;
  char *errstr = NULL;
  int uri_len, ssl_index;
  int is_put;
  int auth_get;
  struct file file = STRUCT_FILE_INITIALIZER;
  char *query_string = NULL;
  char *uri = NULL;
  int x;

  prepare_request(conn);

  ri = &conn->request_info;
  if ((uri = ri->uri) == NULL)
    return;

  conn = freeze_conn(conn);
  path = convert_uri_to_file_name(conn, &file);

  is_put   = is_put_or_delete_request(conn);
  auth_get = check_authorization(conn,path);

  // Perform redirect and auth checks before calling begin_request() handler.
  // Otherwise, begin_request() would need to perform auth checks and redirects.
#ifndef CIL
  if (!conn->client.is_ssl && conn->client.ssl_redir &&
      (ssl_index = get_first_ssl_listener_index(conn->ctx)) > -1)
#else
  if (nondet())
#endif
  {
    redirect_to_https_port(conn, ssl_index);
  }
  else if (is_put)
  {
    if (conn->ctx->config[PUT_DELETE_PASSWORDS_FILE] == NULL ||
                      !is_authorized_for_put(conn))
    {
      send_authorization_request(conn);
    }
    else if (ri->request_method &&
             !strcmp(ri->request_method, mg_freeze_string("PUT")))
    {
      if (is_authorized_for_put(conn))
      {
        put_file(conn, path);
      }
    }
    else if (ri->request_method &&
             !strcmp(ri->request_method, mg_freeze_string("DELETE")))
      {
        if (mg_remove(conn, path) == 0) {
          send_http_error(conn, 200, "OK", "");
        } else {
//          asprintf(&errstr, "remove(%s): %s", path, strerror(ERRNO));
          send_http_error(conn, 500, http_500_error, "remove");
        }
      }
  }
  else if (!auth_get)
  {
    send_authorization_request(conn);
  }
#ifndef CIL
  else if (conn->ctx->callbacks.begin_request != NULL &&
           conn->ctx->callbacks.begin_request(conn))
  {
    //    csolve_assert(0);
    // Do nothing, callback has served the request
  }
#if defined(USE_WEBSOCKET)
  else if (is_websocket_request(conn)) {
    //csolve_assert(0);
    handle_websocket_request(conn);
  }
#endif
#endif
  else if (ri->request_method && !strcmp(ri->request_method, "OPTIONS"))
  {
    send_options(conn);
  }
  else if (conn->ctx->config[DOCUMENT_ROOT] == NULL)
  {
    send_http_error(conn, 404, "Not Found", "File not Found");
  }
  else if ((file.membuf == NULL && file.modification_time == (time_t) 0) ||
           must_hide_file(conn, path))
  {
    /* send_http_error(conn, 404, "Not Found", "%s", "File not found"); */
    send_http_error(conn, 404, "Not Found", "File not found");
  }
  else if (file.is_directory && ri->uri && (uri_len = strlen(ri->uri)) > 0 &&
           ri->uri[uri_len-1] != '/')
  {
    mg_printf(conn, "HTTP/1.1 301 Moved Permanently\r\n"
              "Location: %s/\r\n\r\n", ri->uri);
  }
  else if (ri->request_method && !strcmp(ri->request_method, "PROPFIND"))
  {
    handle_propfind(conn, path, &file);
  }
  /* else if (file.is_directory && */
  /*          !substitute_index_file(conn, path, sizeof(path), &file)) */
  /* { */
  /*   char *dir = conn->ctx->config[ENABLE_DIRECTORY_LISTING]; */
  /*   if (dir && !mg_strcasecmp(dir, "yes")) { */
  /*     handle_directory_request(conn, path); */
  /*   } else { */
  /*     send_http_error(conn, 403, "Directory Listing Denied", */
  /*                     "Directory listing denied"); */
  /*   } */
  /* } */
#if !defined(NO_CGI)
  else if (conn->ctx->config[CGI_EXTENSIONS] &&
           match_prefix(conn->ctx->config[CGI_EXTENSIONS],
                        strlen(conn->ctx->config[CGI_EXTENSIONS]),
                        path) > 0)
  {
    if (ri->request_method &&
        strcmp(ri->request_method, "POST") &&
        strcmp(ri->request_method, "HEAD") &&
        strcmp(ri->request_method, "GET")) {
      send_http_error(conn, 501, "Not Implemented", "Method not implemented");
      //                      "Method %s is not implemented", ri->request_method);
    } else {
      handle_cgi_request(conn, path);
    }
  }
#endif // !NO_CGI
  else if (conn->ctx->config[SSI_EXTENSIONS] &&
           match_prefix(conn->ctx->config[SSI_EXTENSIONS],
                        strlen(conn->ctx->config[SSI_EXTENSIONS]),
                        path) > 0)
  {
    handle_ssi_file_request(conn, path);
  }
  else if (is_not_modified(conn, &file))
  {
    //send_http_error(conn, 304, "Not Modified", "%s", "");
    send_http_error(conn, 304, "Not Modified", "");
  }
  else
  {
    handle_file_request(conn, path, &file);
  }
}

#if !defined(CIL)

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
      /* send_http_error(conn, 500, "Server Error", "%s", ebuf); */
      send_http_error(conn, 500, "Server Error", ebuf);
      conn->must_close = 1;
    } else if (!is_valid_uri(conn->request_info.uri)) {
      snprintf(ebuf, sizeof(ebuf), "Invalid URI: [%s]", ri->uri);
      //send_http_error(conn, 400, "Bad Request", "%s", ebuf);
      send_http_error(conn, 400, "Bad Request", ebuf);
    } else if (strcmp(ri->http_version, "1.0") &&
               strcmp(ri->http_version, "1.1")) {
      snprintf(ebuf, sizeof(ebuf), "Bad HTTP version: [%s]", ri->http_version);
      //send_http_error(conn, 505, "Bad HTTP version", "%s", ebuf);
      send_http_error(conn, 505, "Bad HTTP version", ebuf);
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
#endif
