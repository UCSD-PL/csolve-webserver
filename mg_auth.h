#include "mongoose.h"
#include "mongoose-policy.h"

#include "mg_util.h"

int
REF((V != 0) => ? AUTHORIZED([CONN([conn])]))
check_authorization(struct mg_connection   * OK OK_CONN conn,
                    const NULLTERMSTR char * I STRINGPTR REF(URI([V]) = URI([conn])) path)
  OKEXTERN;

int REF((V != 0) => OK_PUT(conn))
is_authorized_for_put(struct mg_connection * OK OK_CONN conn)
  OKEXTERN;

void
send_authorization_request(struct mg_connection * OK M conn)
  OKEXTERN;
