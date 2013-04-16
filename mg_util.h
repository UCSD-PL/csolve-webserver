#include "mongoose.h"
#include "mongoose-policy.h"

struct file * NNOK
  /* NNREF(FILE([V]) = FILE([path])) */
  NNREF(? AUTH_FILE([CONN([conn]);FILE([V])])) 
  REF(V = 0 => ? NO_AUTHFILE([CONN([conn])]))
  open_auth_file_aux(struct mg_connection * OK GPASSNULL conn, const char NULLTERMSTR FINAL * REF(URI([V]) = URI([conn])) STRINGPTR path)
  OKEXTERN;

char NULLTERMSTR * NNSTART NNSTRINGPTR REF(V = 0 => ? NO_PROTECTFILE([CONN([conn])]))
  NNREF(? AUTH_FILE([CONN([conn]);(V:int)]))
mg_protect_uri_fname(struct mg_connection FINAL *conn)
  OKEXTERN;

/* #define NoAuthNeeded \
  REF(? NO_PROTECTFILE([CONN([V])]))            \
  REF(? NO_AUTHFILE([CONN([V])]))

int REF(? AUTHORIZED([CONN([conn])]))
mg_check_no_auth(struct mg_connection FINAL * NoAuthNeeded conn) OKEXTERN;
*/
