#include <csolve.h>

#define NOAUTHFILE REF(? NO_AUTHFILE([CONN([V])]))
#define NOPROTECTFILE REF(? NO_PROTECTFILE([CONN([V])]))
#define GPASSNULL REF(DEREF([(DEREF([V+20]):ptr)+44]) = 0)
#define NO_AUTH_REQ NOAUTHFILE NOPROTECTFILE GPASSNULL

int //REF(?AUTH_FILE([CONN([conn]);FILE([f])]) => ?AUTHORIZED_BY([CONN([conn]);FILE([f])]))
REF(?AUTHORIZED([CONN([conn])]))
    /* REF(?AUTH_FILE([CONN([conn]);FILE([f])]) => ?AUTHORIZED([CONN([conn])])) */
mg_authorized_def(
  struct mg_connection FINAL * OK REF(? PASSWORD_OK([CONN([V]);PW_ENT([ha1]);DEREF([ah+12])])) conn,
  struct ah            FINAL * REF(AHConnection(V,conn)) ah,
  struct file          FINAL * REF(?AUTH_FILE([CONN([conn]);FILE([V])])) f,
  char NULLTERMSTR FINAL * I STRINGPTR REF(FILE([V]) = FILE([f])) REF(PW_ENT([V]) = PW_ENT([user])) ha1,
  char NULLTERMSTR FINAL * I STRINGPTR REF(FILE([V]) = FILE([f])) REF(PW_ENT([V]) = PW_ENT([domain])) REF(STRING([V]) = STRING([DEREF([ah])])) user,
  char NULLTERMSTR FINAL * I STRINGPTR REF(FILE([V]) = FILE([f])) REF(PW_ENT([V]) = PW_ENT([user])) REF(STRING([V]) = STRING([DEREF([(DEREF([conn+20]):ptr)+20])])) domain
  )
  OKEXTERN;

int REF(? AUTH_FILE([CONN([conn]);FILE([f])]))
mg_authfile_def(
  struct mg_connection FINAL * OK NOPROTECTFILE conn,
  struct file FINAL * OK REF(FILE([V]) = (DEREF([(DEREF([conn+20]):ptr)+44]) : int)) f
  )
  OKEXTERN;

int REF(? AUTH_FILE([CONN([conn]);FILE([f])]))
mg_put_authfile_def(
  struct mg_connection FINAL * OK conn,
  struct file FINAL * OK REF(FILE([V]) = (DEREF([(DEREF([conn+20]):ptr)+8])  : int)) f
  )
  OKEXTERN;

/* int REF(?AUTHORIZED([CONN([conn])])) */
/* mg_authorized_erase_file( */
/*   struct mg_connection FINAL * OK REF(?AUTHORIZED_BY([CONN([V]);FILE([f])])) conn, */
/*   struct file FINAL *f */
/*   ) */
/*   OKEXTERN; */

char NULLTERMSTR * I STRINGPTR LOC(L)
mg_freeze_string(
  char NULLTERMSTR FINAL * STRINGPTR LOC(L)
  )
  OKEXTERN;

int REF(? AUTHORIZED([CONN([conn])]))
mg_no_auth_file(
  struct mg_connection FINAL * OK NO_AUTH_REQ conn
  )
  OKEXTERN;
