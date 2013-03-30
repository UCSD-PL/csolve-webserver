#include "mongoose.h"

struct file * NNOK NNREF(FILE([V]) = FILE([path]))
open_auth_file_aux(struct mg_connection *conn, const char NULLTERMSTR FINAL * STRINGPTR path)
  OKEXTERN;

char NULLTERMSTR * START STRINGPTR
mg_protect_uri_fname(struct mg_connection FINAL *conn) OKEXTERN;

int REF((V != 0) => ? AUTHORIZED([CONN([conn])]))
mg_check_no_auth(struct mg_connection FINAL *conn) OKEXTERN;
