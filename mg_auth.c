#include "mongoose.h"
#include "mongoose-policy.h"
#include "mg_util.h"
#include "mg_auth.h"
#include <errno.h>

char NULLTERMSTR FINAL * I STRINGPTR nondet_string() OKEXTERN;

// V = 1 => Auth(conn)
// Authorize against the opened passwords file. Return 1 if authorized.
int
REF((V != 0) => ? AUTHORIZED_BY([CONN([conn]);FILE([filep])]))
authorize(struct mg_connection FINAL * OK OK_CONN conn,
          struct file                * OK REF(?AUTH_FILE([CONN([conn]);FILE([V])])) filep)
{
  struct ah ah;
  struct pw_ent *pw;
  char *auth_domain;
  char *line, *f_user, *ha1, *f_domain, buf[MG_BUF_LEN], *p;
  int qed;

  if (!parse_auth_header(conn, buf, sizeof(buf), &ah)) {
    return 0;
  }

  // Loop over passwords file
  p = (char *) filep->membuf;
  while ((line = mg_readline(256, filep, &p)) != NULL)
  {
    if((pw = parse_password_line(line)) == NULL) {
      continue;
    }

    f_user      = pw->user;
    f_domain    = pw->domain;
    ha1         = pw->ha1;
    auth_domain = conn->ctx->config[AUTHENTICATION_DOMAIN];

    free(line);
    if (!strcmp(ah.user, f_user)
        && auth_domain
        && !strcmp(auth_domain, f_domain))
    {
      if (check_password(conn->request_info.request_method, ha1, ah.uri,
                         ah.nonce, ah.nc, ah.cnonce, ah.qop, ah.response))
      {
        qed = mg_authorized_def(conn, &ah, filep, ha1, f_user, f_domain);
        return 1;
      }
    }
  }

  return 0;
}

// Use the global passwords file, if specified by auth_gpass option,
// or search for .htpasswd in the requested directory.
struct file *
open_auth_file(struct mg_connection   * OK conn,
               const char NULLTERMSTR * STRINGPTR path)
{
  struct file *ret = NULL;
  const char *e, *gpass = conn->ctx->config[GLOBAL_PASSWORDS_FILE];

  if (gpass != NULL)
  {
    // Use global passwords file
    if ((ret = mg_fopena(conn, gpass, "r")) == NULL)
    {
      cry(conn, "fopen(%s): %s", gpass, strerror(ERRNO));
    }
  }
  else
  {
    ret = open_auth_file_aux(conn, path);
  }

  return ret;
}

// Return 1 if request is authorised, 0 otherwise.
int
REF((V != 0) => ? AUTHORIZED([CONN([conn])]))
check_authorization(struct mg_connection * OK OK_CONN conn, const NULLTERMSTR char * STRINGPTR path)
  CHECK_TYPE
{
  char *fname;
  //  struct file file = STRUCT_FILE_INITIALIZER;
  struct file *filep = NULL;
  struct file *auth_file;
  int authorized = 0;
  int file_ok;
  int qed;

  if (!conn->request_info.uri)
    return 0;

  fname = mg_protect_uri_fname(conn);
  if (fname && ((filep = mg_fopena(conn, fname, "r")) == NULL))
  {
    /* cry(conn, "%s: cannot open %s: %s", __func__, fname, strerror(errno)); */
    return 0;
  }
  else if (!fname)
  {
    filep = open_auth_file(conn, path);
  }

  /** If there was an auth_file to open, then auth. Otherwise no auth */
  if (filep)
  {
    if(is_file_opened(filep))
    {
      //OK
      file_ok = mg_bless_passwd(conn,filep);
      authorized = authorize(conn, filep);
      if (authorized) {
        qed = mg_authorized_erase_file(conn,filep);
        mg_fclose(filep);
        return 1;
      }
    }
    return 0;
  }

  file_ok = mg_check_no_auth(conn);
  return 1;
}

int
REF((V != 0) => OK_PUT(conn))
is_authorized_for_put(struct mg_connection * OK OK_CONN conn)
  CHECK_TYPE
{
  struct file *filep;
  const char *passfile = conn->ctx->config[PUT_DELETE_PASSWORDS_FILE];
  int ret = 0;
  int file_ok;

  if (passfile != NULL && (filep = mg_fopena(conn, passfile, "r")) != NULL) {
    file_ok = mg_bless_passwd(conn,filep);
    ret = authorize(conn, filep);
    mg_fclose(filep);
  }

  return ret;
}

void
send_authorization_request(struct mg_connection * OK M conn)
  CHECK_TYPE
{
  conn->status_code = 401;
  mg_printf(conn,
            "HTTP/1.1 401 Unauthorized\r\n"
            "Content-Length: 0\r\n"
            "WWW-Authenticate: Digest qop=\"auth\", "
            "realm=\"%s\", nonce=\"%lu\"\r\n\r\n",
            conn->ctx->config[AUTHENTICATION_DOMAIN],
            (unsigned long) time(NULL));
}
