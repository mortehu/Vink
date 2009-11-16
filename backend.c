#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <err.h>

#include <postgresql/libpq-fe.h>


static PGconn* pg; /* Database connection handle */
static PGresult* pgresult;
static int pgtuplecount;
static char* last_sql;

/* Remember: Only one result context; store your result before executing another
 * query.
 *
 * Reason: Many queries have a lot of error return paths, and manually freeing
 * the result object would suck.
 */
static int
sql_exec(const char* _query, ...)
{
  static char numbufs[10][128];
  const char* args[10];
  char* c;
  char* query;
  int argcount = 0;
  va_list ap;
  int rowsaffected, n;

  n = strlen(_query);
  query = malloc(n + 1);
  strcpy(query, _query);

  if(pgresult)
    PQclear(pgresult);

  va_start(ap, _query);

  for(c = query; *c; ++c)
    {
      if(*c == '%')
        {
          switch(*(c + 1))
            {
            case 's':

              args[argcount] = va_arg(ap, const char*);

              break;

            case 'd':

              snprintf(numbufs[argcount], 127, "%d", va_arg(ap, int));
              args[argcount] = numbufs[argcount];

              break;

            case 'u':

              snprintf(numbufs[argcount], 127, "%u", va_arg(ap, unsigned int));
              args[argcount] = numbufs[argcount];

              break;

            case 'f':

              snprintf(numbufs[argcount], 127, "%f", va_arg(ap, double));
              args[argcount] = numbufs[argcount];

              break;

            default:

              continue;
            }

          c[0] = '$';
          c[1] = '1' + argcount;
          ++argcount;
        }
    }

  va_end(ap);

  free(last_sql);
  last_sql = strdup(query);
  pgresult = PQexecParams(pg, query, argcount, 0, args, 0, 0, 0);

  if(PQresultStatus(pgresult) == PGRES_FATAL_ERROR)
    errx(EXIT_FAILURE, "PostgreSQL query failed: %s", PQerrorMessage(pg));

  pgtuplecount = PQntuples(pgresult);
  rowsaffected = strtol(PQcmdTuples(pgresult), 0, 0);

  return rowsaffected;
}

void
backend_init()
{
  int i;

  pg = PQconnectdb("dbname=filmlex user=filmlex_write password=Y32m8fmexn");

  if(PQstatus(pg) != CONNECTION_OK)
    errx(EXIT_FAILURE, "PostgreSQL connection failed: %s\n", PQerrorMessage(pg));

  sql_exec("SELECT p.blip_id, p.contact, c.jid FROM vink_participants p NATURAL JOIN vink_contacts c WHERE NOT propagated");

  for(i = 0; i < pgtuplecount; ++i)
    {
      const char *blip_id;
      char *jid_string, *delta_base64;
      struct xmpp_jid jid;

      blip_id = sql_value(i, 0);
      jid_string = strdup(sql_value(i, 1));

      xmpp_parse_jid(&jid, jid_string);

      xmpp_queue_stanza(jid.domain,
                        "<message type='normal'>"
                        "<request xmlns='urn:xmpp:receipts'/>"
                        "<event xmlns='http://jabber.org/protocol/pubsub#event'>"
                        "<items>"
                        "<item>"
                        "<wavelet-update xmlns='http://waveprotocol.org/protocol/0.2/waveserver' wavelet-name='v-%s'>"
                        "<applied-delta>"
                        "<![CDATA[%s]]>"
                        "</applied-delta>"
                        "</wavelet-update>"
                        "</item>"
                        "</items>"
                        "</event>",
                        blip_id, delta_base64);

      //.const char *to, const char *format, ...)
      free(jid_string);
    }
}
