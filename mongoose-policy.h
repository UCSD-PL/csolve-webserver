#include <csolve.h>
#include "mongoose.h"

/*
  Password_OK(response, FILE(pwent))
  STRING(user)   = STRING(pwent->user)
  STRING(domain) = STRING(pwent->domain)
  CONN(user)     = CONN(conn)
  CONN(response) = CONN(conn)
  ===================================
  AuthorizedBy(conn,FILE(pwent))
*/

int REF(?AUTH_FILE([CONN([conn]);FILE([f])]) => ?AUTHORIZED([CONN([conn])]))
mg_authorized_def(
  struct mg_connection FINAL * OK REF(? PASSWORD_OK([CONN([V]);FILE([f])])) conn,
  struct ah            FINAL * REF(AHConnection(V,conn)) ah,
  struct file          FINAL * f,
  char NULLTERMSTR FINAL * STRINGPTR REF(FILE([V]) = FILE([f])) user,
  char NULLTERMSTR FINAL * STRINGPTR REF(FILE([V]) = FILE([f])) domain
  )
  OKEXTERN;

int REF(? AUTH_FILE([CONN([conn]);FILE([f])]))
mg_bless_passwd(struct mg_connection FINAL *conn, struct file FINAL * NNOK f)
  OKEXTERN;
