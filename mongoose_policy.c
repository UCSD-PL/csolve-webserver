#include "mongoose.h"
#include "mongoose-policy.h"

int
mg_authorized_def(
  struct mg_connection FINAL * OK REF(? PASSWORD_OK([CONN([V]);ha1])) conn,
  struct ah            FINAL * REF(AHConnection(V,conn)) ah,
  struct file          FINAL * f,
  char NULLTERMSTR FINAL * STRINGPTR REF(FILE([V]) = FILE([f])) REF(PW_ENT([V]) = PW_ENT([user]))   ha1,
  char NULLTERMSTR FINAL * STRINGPTR REF(FILE([V]) = FILE([f])) REF(PW_ENT([V]) = PW_ENT([domain])) user,
  char NULLTERMSTR FINAL * STRINGPTR REF(FILE([V]) = FILE([f])) REF(PW_ENT([V]) = PW_ENT([user]))  domain
  )
{
  return 1;
}

int REF(?AUTHORIZED([CONN([conn])]))
mg_authorized_erase_file(
  struct mg_connection FINAL * OK REF(?AUTHORIZED_BY([CONN([V]);FILE([f])])) conn,
  struct file FINAL *f
  )
{
  return 1;
}

int REF(?AUTH_FILE([CONN([conn]);FILE([f])]))
mg_bless_passwd(struct mg_connection FINAL *conn, struct file FINAL * NNOK f)
{
  return 1;
}

char NULLTERMSTR * I STRINGPTR LOC(L)
mg_freeze_string(char NULLTERMSTR FINAL * STRINGPTR LOC(L) s)
{
  return s;
}
