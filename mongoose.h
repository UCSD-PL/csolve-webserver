// Copyright (c) 2004-2012 Sergey Lyubka
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#ifndef MONGOOSE_HEADER_INCLUDED
#define  MONGOOSE_HEADER_INCLUDED

#ifdef __linux__
#define _XOPEN_SOURCE 600     // For flockfile() on Linux
#endif

#include <csolve.h>
#include <stdio.h>
#include <stddef.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <limits.h>
#ifndef O_BINARY
#define O_BINARY  0
#endif // O_BINARY
#define closesocket(a) close(a)
#define mg_mkdir(x, y) mkdir(x, y)
#define mg_remove(x) remove(x)
#define mg_sleep(x) usleep((x) * 1000)
#define ERRNO errno
#define INVALID_SOCKET (-1)
#define INT64_FMT PRId64
typedef int SOCKET;
#define WINCDECL

#define MG_BUF_LEN 8192
#define PASSWORDS_FILE_NAME ".htpasswd"
extern const char *http_500_error;

// Macros for enabling compiler-specific checks for printf-like arguments.
#undef PRINTF_FORMAT_STRING
#if _MSC_VER >= 1400
#include <sal.h>
#if _MSC_VER > 1400
#define PRINTF_FORMAT_STRING(s) _Printf_format_string_ s
#else
#define PRINTF_FORMAT_STRING(s) __format_string s
#endif
#else
#define PRINTF_FORMAT_STRING(s) s
#endif

#ifdef __GNUC__
#define PRINTF_ARGS(x, y) __attribute__((format(printf, x, y)))
#else
#define PRINTF_ARGS(x, y)
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#if defined(NO_SSL_DL) || defined(CIL)
#include <openssl/ssl.h>
#else
// SSL loaded dynamically from DLL.
// I put the prototypes here to be independent from OpenSSL source installation.
typedef struct ssl_st SSL;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_ctx_st SSL_CTX;

struct ssl_func {
  const char *name;   // SSL function name
  void  (*ptr)(void); // Function pointer
};

#define SSL_free (* (void (*)(SSL *)) ssl_sw[0].ptr)
#define SSL_accept (* (int (*)(SSL *)) ssl_sw[1].ptr)
#define SSL_connect (* (int (*)(SSL *)) ssl_sw[2].ptr)
#define SSL_read (* (int (*)(SSL *, void *, int)) ssl_sw[3].ptr)
#define SSL_write (* (int (*)(SSL *, const void *,int)) ssl_sw[4].ptr)
#define SSL_get_error (* (int (*)(SSL *, int)) ssl_sw[5].ptr)
#define SSL_set_fd (* (int (*)(SSL *, SOCKET)) ssl_sw[6].ptr)
#define SSL_new (* (SSL * (*)(SSL_CTX *)) ssl_sw[7].ptr)
#define SSL_CTX_new (* (SSL_CTX * (*)(SSL_METHOD *)) ssl_sw[8].ptr)
#define SSLv23_server_method (* (SSL_METHOD * (*)(void)) ssl_sw[9].ptr)
#define SSL_library_init (* (int (*)(void)) ssl_sw[10].ptr)
#define SSL_CTX_use_PrivateKey_file (* (int (*)(SSL_CTX *, \
        const char *, int)) ssl_sw[11].ptr)
#define SSL_CTX_use_certificate_file (* (int (*)(SSL_CTX *, \
        const char *, int)) ssl_sw[12].ptr)
#define SSL_CTX_set_default_passwd_cb \
  (* (void (*)(SSL_CTX *, mg_callback_t)) ssl_sw[13].ptr)
#define SSL_CTX_free (* (void (*)(SSL_CTX *)) ssl_sw[14].ptr)
#define SSL_load_error_strings (* (void (*)(void)) ssl_sw[15].ptr)
#define SSL_CTX_use_certificate_chain_file \
  (* (int (*)(SSL_CTX *, const char *)) ssl_sw[16].ptr)
#define SSLv23_client_method (* (SSL_METHOD * (*)(void)) ssl_sw[17].ptr)
#define SSL_pending (* (int (*)(SSL *)) ssl_sw[18].ptr)
#define SSL_CTX_set_verify (* (void (*)(SSL_CTX *, int, int)) ssl_sw[19].ptr)

#define CRYPTO_num_locks (* (int (*)(void)) crypto_sw[0].ptr)
#define CRYPTO_set_locking_callback \
  (* (void (*)(void (*)(int, int, const char *, int))) crypto_sw[1].ptr)
#define CRYPTO_set_id_callback \
  (* (void (*)(unsigned long (*)(void))) crypto_sw[2].ptr)
#define ERR_get_error (* (unsigned long (*)(void)) crypto_sw[3].ptr)
#define ERR_error_string (* (char * (*)(unsigned long,char *)) crypto_sw[4].ptr)

// set_ssl_option() function updates this array.
// It loads SSL library dynamically and changes NULLs to the actual addresses
// of respective functions. The macros above (like SSL_connect()) are really
// just calling these functions indirectly via the pointer.
static struct ssl_func ssl_sw[] = {
  {"SSL_free",   NULL},
  {"SSL_accept",   NULL},
  {"SSL_connect",   NULL},
  {"SSL_read",   NULL},
  {"SSL_write",   NULL},
  {"SSL_get_error",  NULL},
  {"SSL_set_fd",   NULL},
  {"SSL_new",   NULL},
  {"SSL_CTX_new",   NULL},
  {"SSLv23_server_method", NULL},
  {"SSL_library_init",  NULL},
  {"SSL_CTX_use_PrivateKey_file", NULL},
  {"SSL_CTX_use_certificate_file",NULL},
  {"SSL_CTX_set_default_passwd_cb",NULL},
  {"SSL_CTX_free",  NULL},
  {"SSL_load_error_strings", NULL},
  {"SSL_CTX_use_certificate_chain_file", NULL},
  {"SSLv23_client_method", NULL},
  {"SSL_pending", NULL},
  {"SSL_CTX_set_verify", NULL},
  {NULL,    NULL}
};

// Similar array as ssl_sw. These functions could be located in different lib.
#if !defined(NO_SSL)
static struct ssl_func crypto_sw[] = {
  {"CRYPTO_num_locks",  NULL},
  {"CRYPTO_set_locking_callback", NULL},
  {"CRYPTO_set_id_callback", NULL},
  {"ERR_get_error",  NULL},
  {"ERR_error_string", NULL},
  {NULL,    NULL}
};
#endif // NO_SSL
#endif // NO_SSL_DL

// NOTE(lsm): this enum shoulds be in sync with the config_options below.
enum {
  CGI_EXTENSIONS,
  CGI_ENVIRONMENT,
  PUT_DELETE_PASSWORDS_FILE,
  CGI_INTERPRETER,
  PROTECT_URI,
  AUTHENTICATION_DOMAIN,
  SSI_EXTENSIONS,
  THROTTLE,
  ACCESS_LOG_FILE,
  ENABLE_DIRECTORY_LISTING,
  ERROR_LOG_FILE,
  GLOBAL_PASSWORDS_FILE,
  INDEX_FILES,
  ENABLE_KEEP_ALIVE,
  ACCESS_CONTROL_LIST,
  EXTRA_MIME_TYPES,
  LISTENING_PORTS,
  DOCUMENT_ROOT,
  SSL_CERTIFICATE,
  NUM_THREADS,
  RUN_AS_USER,
  REWRITE,
  HIDE_FILES,
  REQUEST_TIMEOUT,
  NUM_OPTIONS
};


#define NOPTIONS 24

static const char *config_options[] = {
  "cgi_pattern", "**.cgi$|**.pl$|**.php$",
  "cgi_environment", NULL,
  "put_delete_auth_file", NULL,
  "cgi_interpreter", NULL,
  "protect_uri", NULL,
  "authentication_domain", "mydomain.com",
  "ssi_pattern", "**.shtml$|**.shtm$",
  "throttle", NULL,
  "access_log_file", NULL,
  "enable_directory_listing", "yes",
  "error_log_file", NULL,
  "global_auth_file", NULL,
  "index_files",
    "index.html,index.htm,index.cgi,index.shtml,index.php,index.lp",
  "enable_keep_alive", "no",
  "access_control_list", NULL,
  "extra_mime_types", NULL,
  "listening_ports", "8080",
  "document_root",  ".",
  "ssl_certificate", NULL,
  "num_threads", "50",
  "run_as_user", NULL,
  "url_rewrite_patterns", NULL,
  "hide_files_patterns", NULL,
  "request_timeout_ms", "30000",
  NULL
};

// Unified socket address. For IPv6 support, add IPv6 address structure
// in the union u.
union usa {
  struct sockaddr sa;
  struct sockaddr_in sin;
#if defined(USE_IPV6)
  struct sockaddr_in6 sin6;
#endif
};

// Describes a string (chunk of memory).
struct vec {
  const NULLTERMSTR char * NNSTART NNSTRINGPTR NNSIZE_GE(len) FINAL ptr;
  size_t REF(V >= 0) FINAL len;
};

struct file {
  int is_directory;
  time_t modification_time;
  int64_t size;
  #ifdef CIL
  CSOLVE_IO_FILE_PTR NNOK LOC(FP) fp;
  #else
  FILE *fp;
  #endif
  const char NULLTERMSTR * NNOK NNSTRINGPTR LOC(MB) membuf;   // Non-NULL if file data is in memory
};
#define STRUCT_FILE_INITIALIZER {0, 0, 0, NULL, NULL}

#define SOCKET int
// Describes listening socket, or socket which was accept()-ed by the master
// thread and queued for future handling by the worker thread.
struct socket {
  SOCKET sock;          // Listening socket
  union usa lsa;        // Local socket address
  union usa rsa;        // Remote socket address
  unsigned is_ssl:1;    // Is port SSL-ed
  unsigned ssl_redir:1; // Is port supposed to redirect everything to SSL port
};

#ifdef CIL
#define CSOLVE_HIDE_DECLS(x)
#else
#define CSOLVE_HIDE_DECLS(x) x
#endif

struct mg_context;     // Handle for the HTTP service itself
struct mg_connection;  // Handle for the individual connection

// This structure needs to be passed to mg_start(), to let mongoose know
// which callbacks to invoke. For detailed description, see
// https://github.com/valenok/mongoose/blob/master/UserManual.md
struct mg_callbacks {
  int  (*begin_request)(struct mg_connection *);
  void (*end_request)(const struct mg_connection *, int reply_status_code);
  int  (*log_message)(const struct mg_connection *, const char *message);
  int  (*init_ssl)(void *ssl_context, void *user_data);
  int (*websocket_connect)(const struct mg_connection *);
  void (*websocket_ready)(struct mg_connection *);
  int  (*websocket_data)(struct mg_connection *, int flags,
                         char *data, size_t data_len);
  const char * (*open_file)(const struct mg_connection *,
                             const char *path, size_t *data_len);
  void (*init_lua)(struct mg_connection *, void *lua_context);
  void (*upload)(struct mg_connection *, const char *file_name);
  int  (*http_error)(struct mg_connection *, int status);
};


struct mg_context {
  CSOLVE_HIDE_DECLS
  (
  volatile int stop_flag;         // Should we stop event loop
  SSL_CTX *ssl_ctx;               // SSL context
  )
  char NULLTERMSTR * NNSTRINGPTR LOC(CTX_CFG) config[NUM_OPTIONS]; // Mongoose configuration parameters
  CSOLVE_HIDE_DECLS
  (
      struct mg_callbacks callbacks;  // User-defined callback function
      void *user_data;                // User-defined data

      struct socket *listening_sockets;
      int num_listening_sockets;

      volatile int num_threads;  // Number of threads
      pthread_mutex_t mutex;     // Protects (max|num)_threads
      pthread_cond_t  cond;      // Condvar for tracking workers terminations

      struct socket queue[20];   // Accepted sockets
      volatile int sq_head;      // Head of the socket queue
      volatile int sq_tail;      // Tail of the socket queue
      pthread_cond_t sq_full;    // Signaled when socket is produced
      pthread_cond_t sq_empty;   // Signaled when socket is consumed
  )
};

// This structure contains information about the HTTP request.
struct mg_request_info {
  const char NULLTERMSTR * NNVALIDPTR NNSTRINGPTR FINAL  I request_method; // "GET", "POST", etc
  const char NULLTERMSTR * NNVALIDPTR NNSTRINGPTR LOC(U) M uri;            // URL-decoded URI
  const char NULLTERMSTR * NNVALIDPTR NNSTRINGPTR http_version;   // E.g. "1.0", "1.1"
  const char NULLTERMSTR * NNVALIDPTR NNSTRINGPTR LOC(U) M query_string;   // URL part after '?', not including '?', or NULL
  const char NULLTERMSTR * NNVALIDPTR NNSTRINGPTR remote_user;    // Authenticated user, or NULL if no auth used
  CSOLVE_HIDE_DECLS
  (
    long remote_ip;             // Client's IP address
    int remote_port;            // Client's port
    int is_ssl;                 // 1 if SSL-ed, 0 if not
    void *user_data;            // User data pointer passed to mg_start()

    int num_headers;            // Number of HTTP headers
    struct mg_header {
      const char *name;         // HTTP header name
      const char *value;        // HTTP header value
    } http_headers[64];         // Maximum 64 headers
  )
};

#define OK_URI  REF(DEREF([V]) != 0)
#define OK_CONN REF(CONN([V]) = CONN([DEREF([V])]))

struct mg_connection {
  struct mg_request_info request_info;
  struct mg_context INST(CTX_CFG,CTX_CFG) * OK ctx;
  CSOLVE_HIDE_DECLS
  (
    SSL *ssl;                   // SSL descriptor
    SSL_CTX *client_ssl_ctx;    // SSL context for client connections
  )
  CSOLVE_HIDE_DECLS
  (
  struct socket client;       // Connected client
    time_t birth_time;          // Time when request was received
  )
    int64_t num_bytes_sent;     // Total bytes sent to client
  CSOLVE_HIDE_DECLS
  (
    int64_t content_len;        // Content-Length header value
    int64_t consumed_content;   // How many bytes of content have been read
    char *buf;                  // Buffer for received data
    char *path_info;            // PATH_INFO part of the URL
  )
    int must_close;             // 1 if connection must be closed
  CSOLVE_HIDE_DECLS
  (
    int buf_size;               // Buffer size
    int request_len;            // Size of the request + headers in a buffer
    int data_len;               // Total size of data in a buffer
  )
    int status_code;            // HTTP reply status code, e.g. 200
    int throttle;               // Throttling, bytes/sec. <= 0 means no throttle
  CSOLVE_HIDE_DECLS
  (
    time_t last_throttle_time;  // Last time throttled data was sent
    int64_t last_throttle_bytes;// Bytes sent this second
  )
};

struct de {
  struct mg_connection *conn;
  char NULLTERMSTR *file_name;
  struct file file;
};

struct dir_scan_data {
  struct de * NNSTART NNVALIDPTR ARRAY entries;
  int num_entries;
  int arr_size;
};

// Parsed Authorization header
struct ah {
  char NULLTERMSTR * FINAL NNOK NNSTRINGPTR I user;
  char NULLTERMSTR * FINAL NNOK NNSTRINGPTR I uri;
  char NULLTERMSTR * FINAL NNOK NNSTRINGPTR I cnonce;
  char NULLTERMSTR * FINAL NNOK NNSTRINGPTR I response;
  char NULLTERMSTR * FINAL NNOK NNSTRINGPTR I qop;
  char NULLTERMSTR * FINAL NNOK NNSTRINGPTR I nc;
  char NULLTERMSTR * FINAL NNOK NNSTRINGPTR I nonce;
};
////////////////////////////////


//////////////////////////////////////////////////////
// ABAKST Expose functions to mg_connection (et al?)
//////////////////////////////////////////////////////
void send_http_error(struct mg_connection *, int, const char NULLTERMSTR *,
                            PRINTF_FORMAT_STRING(const char NULLTERMSTR *fmt), ...)
  PRINTF_ARGS(4, 5) OKEXTERN;
void send_options(struct mg_connection *conn);
void put_file(struct mg_connection *conn, const char *path);

int mg_snprintf(struct mg_connection *conn,
                char NULLTERMSTR * STRINGPTR /* SIZE_GE(buflen)  */buf,
                size_t buflen,
                const char *fmt,...)
                /* PRINTF_FORMAT_STRING(const char *fmt), ...) */
  PRINTF_ARGS(4, 5) OKEXTERN;

int mg_remove(const char *path);

int
REF(V != 0 => (DEREF([filep + 16]) > 0))
mg_fopen(struct mg_connection INST(CTX_CFG,CTX_CFG) FINAL *conn,
         const char NULLTERMSTR FINAL                     *LOC(CTX_CFG) STRINGPTR path,
         const char NULLTERMSTR FINAL                     *STRINGPTR mode,
         struct file                                      *filep)
  OKEXTERN;

int mg_stat(struct mg_connection   FINAL *conn,
            const char NULLTERMSTR       *STRINGPTR path,
            struct file                  *filep)
  OKEXTERN;

void mg_fclose(struct file *filep) OKEXTERN;

char NULLTERMSTR* NNSTRINGPTR NNSTART NNREF(FILE([V]) = FILE([filep]))
mg_readline(size_t size, struct file INST(MB,MB) *filep, char NULLTERMSTR * NNSTRINGPTR LOC(MB) * OK p)
  OKEXTERN;

char NULLTERMSTR* NNSTRINGPTR
mg_fgets(char NULLTERMSTR * OK STRINGPTR buf, size_t size, struct file INST(MB,MB) *filep, char NULLTERMSTR * NNSTRINGPTR LOC(MB) * OK p)
  OKEXTERN;

void cry(struct mg_connection FINAL * OK conn,
                PRINTF_FORMAT_STRING(const char NULLTERMSTR *fmt), ...)
  PRINTF_ARGS(2, 3) OKEXTERN;

int mg_strcasecmp(const char NULLTERMSTR FINAL * STRINGPTR s1,
                  const char NULLTERMSTR FINAL * STRINGPTR s2) OKEXTERN;

//Eventually move this somewhere else ABAKST
int url_decode(const char NULLTERMSTR FINAL * STRINGPTR SIZE_GE(src_len) LOC(S) src,
               int src_len,
               char NULLTERMSTR * STRINGPTR SIZE_GE(dst_len) LOC(S) dst,
               int dst_len,
               int is_form_url_encoded) OKEXTERN;

void remove_double_dots_and_double_slashes(char NULLTERMSTR * STRINGPTR M s) OKEXTERN;

void convert_uri_to_file_name(struct mg_connection *conn,
                              char NULLTERMSTR * STRINGPTR SIZE_GE(buf_len) buf,
                              size_t buf_len,
                              struct file * OK M filep) OKEXTERN;

int set_throttle(const char NULLTERMSTR * NNSTRINGPTR spec,
                 uint32_t remote_ip,
                 const char NULLTERMSTR * STRINGPTR uri) OKEXTERN;

uint32_t get_remote_ip(const struct mg_connection FINAL *conn) OKEXTERN;
int get_first_ssl_listener_index(const struct mg_context *ctx);
void redirect_to_https_port(struct mg_connection * OK OK_CONN conn, int ssl_index) OKEXTERN;
int is_put_or_delete_request(const struct mg_connection FINAL *conn) OKEXTERN;

// A helper function for traversing a comma separated list of values.
// It returns a list pointer shifted to the next value, or NULL if the end
// of the list found.
// Value is stored in val vector. If value has form "x=y", then eq_val
// vector is initialized to point to the "y" part, and val vector length
// is adjusted to point only to "x".
const char NULLTERMSTR* NNSTRINGPTR LOC(L)
next_option(const char NULLTERMSTR * STRINGPTR LOC(L) list,
            struct vec *val,
            struct vec *eq_val) OKEXTERN;

int is_file_opened(const struct file FINAL *filep) OKEXTERN;

#define AHParsed(__ah) (V != 0) =>  \
    &&[DEREF([__ah+0]) > 0;         \
       DEREF([__ah+4]) > 0;         \
       DEREF([__ah+8]) > 0;          \
       DEREF([__ah+12]) > 0;         \
       DEREF([__ah+16]) > 0;         \
       DEREF([__ah+20]) > 0;         \
       DEREF([__ah+24]) > 0]

#define AHConnection(__ah, __conn) (V != 0) =>   \
    &&[CONN([DEREF([__ah+0])])  = CONN([__conn]);        \
       CONN([DEREF([__ah+4])])  = CONN([__conn]);        \
       CONN([DEREF([__ah+8])])  = CONN([__conn]);        \
       CONN([DEREF([__ah+12])]) = CONN([__conn]);         \
       CONN([DEREF([__ah+16])]) = CONN([__conn]);         \
       CONN([DEREF([__ah+20])]) = CONN([__conn]);         \
       CONN([DEREF([__ah+24])]) = CONN([__conn])]
    
int REF(AHParsed(ah)) REF(AHConnection(ah, conn))
parse_auth_header(struct mg_connection FINAL *conn, char NULLTERMSTR FINAL *buf,
                  size_t buf_size, struct ah FINAL *ah)
  OKEXTERN;

struct pw_ent {
  char NULLTERMSTR * STRINGPTR I FINAL user;
  char NULLTERMSTR * STRINGPTR I FINAL domain;
  char NULLTERMSTR * STRINGPTR I FINAL ha1;
};

#define NNOK_PW(__s)                                           \
  NNREF(&&[FILE([DEREF([V])]) = FILE([__s]);                   \
           FILE([DEREF([V+4])]) = FILE([__s]);                 \
           FILE([DEREF([V+8])]) = FILE([__s])])

struct pw_ent * NNOK NNOK_PW(line)
parse_password_line(char NULLTERMSTR * STRINGPTR line) OKEXTERN;
  
int
check_password(const char NULLTERMSTR FINAL * NNSTRINGPTR I method,
               const char NULLTERMSTR FINAL * NNSTRINGPTR I ha1,
               const char NULLTERMSTR FINAL * NNSTRINGPTR I uri,
               const char NULLTERMSTR FINAL * NNSTRINGPTR I nonce,
               const char NULLTERMSTR FINAL * NNSTRINGPTR I nc,
               const char NULLTERMSTR FINAL * NNSTRINGPTR I cnonce,
               const char NULLTERMSTR FINAL * NNSTRINGPTR I qop,
               const char NULLTERMSTR FINAL * REF(CONN([V]) = CONN([method])) NNSTRINGPTR I response)
  OKEXTERN;

int must_hide_file(struct mg_connection *conn, const char *path);
void handle_propfind(struct mg_connection *conn, const char *path,
                     struct file *filep);

// For given directory path, substitute it to valid index file.
// Return 0 if index file has been found, -1 if not found.
// If the file is found, it's stats is returned in stp.
int substitute_index_file(struct mg_connection *conn,
                          char NULLTERMSTR *path,
                          size_t path_len,
                          struct file *filep) OKEXTERN;

#warning "incomplete type for dir_scan_callback?"
void dir_scan_callback(struct de *de, struct dir_scan_data *data) OKEXTERN;

int scan_directory(struct mg_connection *conn,
                   const char NULLTERMSTR *dir,
                   struct dir_scan_data *ds,
                   void (*cb)(struct de *, struct dir_scan_data *)) OKEXTERN;

int compare_dir_entries(const struct de *de1, const struct de *de2) OKEXTERN;

void print_dir_entry(struct de *de) OKEXTERN;
void print_dir_entries(struct dir_scan_data FINAL *data) OKEXTERN;

int match_prefix(const char *pattern, int pattern_len, const char *str);
void handle_cgi_request(struct mg_connection *conn, const char *prog);
void handle_ssi_file_request(struct mg_connection *conn,
                             const char *path);
int is_not_modified(const struct mg_connection *conn,
                    const struct file *filep);
void handle_file_request(struct mg_connection *conn, const char *path,
                         struct file *filep);
void reset_per_request_attributes(struct mg_connection *conn);
int read_request(FILE *fp, struct mg_connection *conn,
                 char *buf, int bufsiz, int *nread);
int parse_http_message(char *buf, int len, struct mg_request_info *ri);
const char *get_header(const struct mg_request_info *ri,
                 const char *name);
int is_valid_uri(const char *uri);
void log_access(const struct mg_connection *conn);
int should_keep_alive(const struct mg_connection *conn);

/**
REFINE process_new_connection
conn:
*conn:
-> 
*/
void process_new_connection(struct mg_connection *conn);
//////////////////////////////////////////////////////



// Start web server.
//
// Parameters:
//   callbacks: mg_callbacks structure with user-defined callbacks.
//   options: NULL terminated list of option_name, option_value pairs that
//            specify Mongoose configuration parameters.
//
// Side-effects: on UNIX, ignores SIGCHLD and SIGPIPE signals. If custom
//    processing is required for these, signal handlers must be set up
//    after calling mg_start().
//
//
// Example:
//   const char *options[] = {
//     "document_root", "/var/www",
//     "listening_ports", "80,443s",
//     NULL
//   };
//   struct mg_context *ctx = mg_start(&my_func, NULL, options);
//
// Refer to https://github.com/valenok/mongoose/blob/master/UserManual.md
// for the list of valid option and their possible values.
//
// Return:
//   web server context, or NULL on error.
struct mg_context *mg_start(const struct mg_callbacks *callbacks,
                            void *user_data,
                            const char **configuration_options);


// Stop the web server.
//
// Must be called last, when an application wants to stop the web server and
// release all associated resources. This function blocks until all Mongoose
// threads are stopped. Context pointer becomes invalid.
void mg_stop(struct mg_context *);


// Get the value of particular configuration parameter.
// The value returned is read-only. Mongoose does not allow changing
// configuration at run time.
// If given parameter name is not valid, NULL is returned. For valid
// names, return value is guaranteed to be non-NULL. If parameter is not
// set, zero-length string is returned.
const char *mg_get_option(const struct mg_context *ctx, const char *name);


// Return array of strings that represent valid configuration options.
// For each option, a short name, long name, and default value is returned.
// Array is NULL terminated.
const char **mg_get_valid_option_names(void);


// Add, edit or delete the entry in the passwords file.
//
// This function allows an application to manipulate .htpasswd files on the
// fly by adding, deleting and changing user records. This is one of the
// several ways of implementing authentication on the server side. For another,
// cookie-based way please refer to the examples/chat.c in the source tree.
//
// If password is not NULL, entry is added (or modified if already exists).
// If password is NULL, entry is deleted.
//
// Return:
//   1 on success, 0 on error.
int mg_modify_passwords_file(const char *passwords_file_name,
                             const char *domain,
                             const char *user,
                             const char *password);


// Return information associated with the request.
struct mg_request_info *mg_get_request_info(struct mg_connection *);


// Send data to the client.
// Return:
//  0   when the connection has been closed
//  -1  on error
//  >0  number of bytes written on success
// CSOLVE:
//   AUTH(conn) || TRUSTED(fmt)
int mg_write(struct mg_connection *, const void *buf, size_t len);


// Send data to the client using printf() semantics.
//
// Works exactly like mg_write(), but allows to do message formatting.
// CSOLVE:
//   AUTH(conn) || TRUSTED(fmt)
int mg_printf(struct mg_connection * OK OK_CONN,
              PRINTF_FORMAT_STRING(const char *fmt), ...) PRINTF_ARGS(2, 3) OKEXTERN;
void mg_printf_inc(struct mg_connection *conn, const char *fmt, ...) PRINTF_ARGS(2, 3) OKEXTERN;

// Send contents of the entire file together with HTTP headers.
// CSOLVE:
//   AUTH(conn) && ACCESS(conn, path)
void mg_send_file(struct mg_connection *conn, const char *path);


// Read data from the remote end, return number of bytes read.
int mg_read(struct mg_connection *, void *buf, size_t len);


// Get the value of particular HTTP header.
//
// This is a helper function. It traverses request_info->http_headers array,
// and if the header is present in the array, returns its value. If it is
// not present, NULL is returned.
const char *mg_get_header(const struct mg_connection *, const char *name);


// Get a value of particular form variable.
//
// Parameters:
//   data: pointer to form-uri-encoded buffer. This could be either POST data,
//         or request_info.query_string.
//   data_len: length of the encoded data.
//   var_name: variable name to decode from the buffer
//   dst: destination buffer for the decoded variable
//   dst_len: length of the destination buffer
//
// Return:
//   On success, length of the decoded variable.
//   On error:
//      -1 (variable not found).
//      -2 (destination buffer is NULL, zero length or too small to hold the
//          decoded variable).
//
// Destination buffer is guaranteed to be '\0' - terminated if it is not
// NULL or zero length.
int mg_get_var(const char *data, size_t data_len,
               const char *var_name, char *dst, size_t dst_len);

// Fetch value of certain cookie variable into the destination buffer.
//
// Destination buffer is guaranteed to be '\0' - terminated. In case of
// failure, dst[0] == '\0'. Note that RFC allows many occurrences of the same
// parameter. This function returns only first occurrence.
//
// Return:
//   On success, value length.
//   On error:
//      -1 (either "Cookie:" header is not present at all or the requested
//          parameter is not found).
//      -2 (destination buffer is NULL, zero length or too small to hold the
//          value).
int mg_get_cookie(const struct mg_connection *,
                  const char *cookie_name, char *buf, size_t buf_len);


// Download data from the remote web server.
//   host: host name to connect to, e.g. "foo.com", or "10.12.40.1".
//   port: port number, e.g. 80.
//   use_ssl: wether to use SSL connection.
//   error_buffer, error_buffer_size: error message placeholder.
//   request_fmt,...: HTTP request.
// Return:
//   On success, valid pointer to the new connection, suitable for mg_read().
//   On error, NULL. error_buffer contains error message.
// Example:
//   char ebuf[100];
//   struct mg_connection *conn;
//   conn = mg_download("google.com", 80, 0, ebuf, sizeof(ebuf),
//                      "%s", "GET / HTTP/1.0\r\nHost: google.com\r\n\r\n");
struct mg_connection *mg_download(const char *host, int port, int use_ssl,
                                  char *error_buffer, size_t error_buffer_size,
                                  PRINTF_FORMAT_STRING(const char *request_fmt),
                                  ...) PRINTF_ARGS(6, 7);


// Close the connection opened by mg_download().
void mg_close_connection(struct mg_connection *conn);


// File upload functionality. Each uploaded file gets saved into a temporary
// file and MG_UPLOAD event is sent.
// Return number of uploaded files.
int mg_upload(struct mg_connection *conn, const char *destination_dir);


// Convenience function -- create detached thread.
// Return: 0 on success, non-0 on error.
typedef void * (*mg_thread_func_t)(void *);
int mg_start_thread(mg_thread_func_t f, void *p);


// Return builtin mime type for the given file name.
// For unrecognized extensions, "text/plain" is returned.
const char *mg_get_builtin_mime_type(const char *file_name);


// Return Mongoose version.
const char *mg_version(void);


// MD5 hash given strings.
// Buffer 'buf' must be 33 bytes long. Varargs is a NULL terminated list of
// ASCIIz strings. When function returns, buf will contain human-readable
// MD5 hash. Example:
//   char buf[33];
//   mg_md5(buf, "aa", "bb", NULL);
void mg_md5(char buf[33], ...);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // MONGOOSE_HEADER_INCLUDED
