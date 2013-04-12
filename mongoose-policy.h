#include <csolve.h>

//"Lemmas"
/*
  Password_OK(response, FILE(pwent))
  STRING(user)   = STRING(pwent->user)
  STRING(domain) = STRING(pwent->domain)
  CONN(user)     = CONN(conn)
  CONN(response) = CONN(conn)
  ===================================
  AuthorizedBy(conn,FILE(pwent))
*/
int REF(?AUTH_FILE([CONN([conn]);FILE([f])]) => ?AUTHORIZED_BY([CONN([conn]);FILE([f])]))
mg_authorized_def(
  struct mg_connection FINAL * OK REF(? PASSWORD_OK([CONN([V]);ha1])) conn,
  struct ah            FINAL * REF(AHConnection(V,conn)) ah,
  struct file          FINAL * f,
  char NULLTERMSTR FINAL * STRINGPTR REF(FILE([V]) = FILE([f])) REF(PW_ENT([V]) = PW_ENT([user]))   ha1,
  char NULLTERMSTR FINAL * STRINGPTR REF(FILE([V]) = FILE([f])) REF(PW_ENT([V]) = PW_ENT([domain])) user,
  char NULLTERMSTR FINAL * STRINGPTR REF(FILE([V]) = FILE([f])) REF(PW_ENT([V]) = PW_ENT([user]))  domain
  )
  OKEXTERN;

int REF(?AUTHORIZED([CONN([conn])]))
mg_authorized_erase_file(
  struct mg_connection FINAL * OK REF(?AUTHORIZED_BY([CONN([V]);FILE([f])])) conn,
  struct file FINAL *f
  ) OKEXTERN;

int REF(?AUTH_FILE([CONN([conn]);FILE([f])]))
mg_bless_passwd(struct mg_connection FINAL *conn, struct file FINAL * NNOK f)
  OKEXTERN;

char NULLTERMSTR * I STRINGPTR LOC(L)
mg_freeze_string(char NULLTERMSTR FINAL * STRINGPTR LOC(L))
OKEXTERN;

int REF(? AUTHORIZED([CONN([conn])]))
mg_no_auth_file(struct mg_connection FINAL * OK REF(? NO_AUTHFILE([CONN([V])])) REF(? NO_PROTECTFILE([CONN([V])])) conn)
OKEXTERN;
