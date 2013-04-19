#include "mongoose.h"
#include "mongoose-policy.h"

#include "mg_util.h"

int
REF((V != 0) => ? AUTHORIZED([CONN([conn])]))
check_authorization(struct mg_connection   INST(CTX_CFG,CTX_CFG) * OK OK_CONN conn,
                    const NULLTERMSTR char * LOC(CTX_CFG) I STRINGPTR REF(URI([V]) = URI([CONN([conn])])) path)
OKEXTERN;

//int REF((V != 0) => OK_PUT(conn))
int REF((V != 0) => ? AUTH_FILE([CONN([conn]);(PUT_FILE_CONFIG(conn):int)]))
    REF((V != 0) => ? AUTHORIZED([CONN([conn])]))
is_authorized_for_put(struct mg_connection * OK OK_CONN conn)
  OKEXTERN;

void
send_authorization_request(struct mg_connection * OK M conn)
  OKEXTERN;
