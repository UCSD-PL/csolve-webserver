#include "mongoose.h"
#include "mongoose-policy.h"

struct file * NNOK
  /* NNREF(FILE([V]) = FILE([path])) */
  NNREF(? AUTH_FILE([CONN([conn]);FILE([V])])) 
  REF(V = 0 => ? NO_AUTHFILE([CONN([conn])]))
  open_auth_file_aux(struct mg_connection INST(CTX_CFG,CTX_CFG)* OK GPASSNULL NOPROTECTFILE conn,
                     const char NULLTERMSTR FINAL * LOC(CTX_CFG) I REF(URI([V]) = URI([CONN([conn])])) STRINGPTR path)
  OKEXTERN;

char NULLTERMSTR * NNSTART NNSTRINGPTR REF(V = 0 => ? NO_PROTECTFILE([CONN([conn])]))
  NNREF(? AUTH_FILE([CONN([conn]);(V:int)]))
mg_protect_uri_fname(struct mg_connection FINAL *conn)
  OKEXTERN;
