#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>

#include <postgresql/libpq-fe.h>

#include "array.h"
#include "backend.h"
#include "tree.h"
#include "vink_internal.h"

static PGconn *pg; /* Database connection handle */
static PGresult *pgresult;
static int tuple_count;
static char *last_sql;

static int
sql_exec(const char *query, ...);

static void
sql_free_result();

#define sql_value(i, j) PQgetvalue(pgresult, (i), (j))

static int
authenticate(struct vink_xmpp_state *state, const char *authzid,
             const char *user, const char *secret)
{
  const char *domain;
  int result = 0;

  domain = vink_config("domain");

  sql_exec("SELECT password FROM users WHERE domain = %s AND username = %s",
           domain, user);

  if(!tuple_count || strcmp(secret, sql_value(0, 0)))
    result = -1;

  sql_free_result();

  return result;
}

/*
  enum vink_protocol protocol;
  enum vink_part_type part_type;

  time_t sent, received;

  const char *content_type;

  const char *id;
  const char *from;
  const char *to;
  const char *subject;
  const char *body;
  size_t body_size;

  const struct vink_header *headers;
  size_t header_count;

  const struct vink_message *parts;
  size_t part_count;

  void *private;
  */
static void
message(struct vink_xmpp_state *state, struct vink_message *message)
{
  int result;

  result = sql_exec("INSERT INTO messages "
                    "(id, protocol, part_type, sent, received, content_type, sender, "
                    "receiver, subject, body) "
                    "VALUES "
                    "(%s, %u, %u, %l, %l, %s, %s, %s, %s, %s)",
                    message->id, message->protocol, message->part_type,
                    (unsigned long long) message->sent,
                    (unsigned long long) message->received,
                    message->content_type, message->from, message->to, message->subject,
                    message->body);

  if(result == -1)
    fprintf(stderr, "Error: %s\n", vink_last_error());

  vink_message_free(message);
}

static void
presence(struct vink_xmpp_state *state, const char *jid,
         enum vink_presence presence)
{
  fprintf(stderr, "Got presence for %s\n", jid);
}

static void
queue_empty(struct vink_xmpp_state *state)
{
  fprintf(stderr, "Queue is empty\n");
}

void
backend_postgresql_init(struct vink_xmpp_callbacks *callbacks)
{
  char *connect_string;

  callbacks->authenticate = authenticate;
  callbacks->message = message;
  callbacks->presence = presence;
  callbacks->queue_empty = queue_empty;

  if(-1 == asprintf(&connect_string,
                    "dbname=%s user=%s password=%s host=%s port=%u",
                    tree_get_string(VINK_config, "backend.database"),
                    tree_get_string(VINK_config, "backend.user"),
                    tree_get_string(VINK_config, "backend.password"),
                    tree_get_string(VINK_config, "backend.host"),
                    (unsigned int) tree_get_integer(VINK_config, "backend.port")))
    err(EXIT_FAILURE, "asprintf failed\n");

  pg = PQconnectdb(connect_string);

  free(connect_string);

  if(PQstatus(pg) != CONNECTION_OK)
    errx(EXIT_FAILURE, "PostgreSQL connection failed: %s\n", PQerrorMessage(pg));

  sql_exec("SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE");

#if 0
  sql_exec("SELECT p.blip_id, p.contact, c.jid FROM vink_participants p NATURAL JOIN vink_contacts c WHERE NOT propagated");

  for(i = 0; i < tuple_count; ++i)
    {
      const char *blip_id;
      char *jid_string, *delta_base64;
      struct xmpp_jid jid;

      blip_id = sql_value(i, 0);
      jid_string = strdup(sql_value(i, 1));

      xmpp_parse_jid(&jid, jid_string);

      /*
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
                        */

      free(jid_string);
    }
#endif
}

static void
sql_free_result()
{
  if(pgresult)
    {
      PQclear(pgresult);
      pgresult = 0;
    }
}

/* Remember: Only one result context; store your result before executing another
 * query.
 *
 * Reason: Many queries have a lot of error return paths, and manually freeing
 * the result object would suck.
 */
static int
sql_exec(const char *query, ...)
{
  static char numbufs[10][128];
  const char *args[10];
  const char *c;
  int argcount = 0;
  va_list ap;
  int rowsaffected;

  ARRAY(char) new_query;

  if(pgresult)
    {
      PQclear(pgresult);
      pgresult = 0;
    }

  va_start(ap, query);

  ARRAY_INIT(&new_query);

  for(c = query; *c; )
    {
      switch(*c)
        {
        case '%':

          ++c;

          switch(*c)
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

            case 'l':

              snprintf(numbufs[argcount], 127, "%lld", va_arg(ap, long long));
              args[argcount] = numbufs[argcount];

              break;

            case 'f':

              snprintf(numbufs[argcount], 127, "%f", va_arg(ap, double));
              args[argcount] = numbufs[argcount];

              break;

            default:

              assert(!"unknown format character");

              return -1;
            }

          ++c;
          ++argcount;

          ARRAY_ADD(&new_query, '$');
          if(argcount >= 10)
            ARRAY_ADD(&new_query, '0' + (argcount / 10));
          ARRAY_ADD(&new_query, '0' + (argcount % 10));

          break;

        default:

          ARRAY_ADD(&new_query, *c);
          ++c;
        }
    }

  va_end(ap);

  ARRAY_ADD(&new_query, 0);

  free(last_sql);
  last_sql = strdup(&ARRAY_GET(&new_query, 0));
  pgresult = PQexecParams(pg, last_sql, argcount, 0, args, 0, 0, 0);

  if(PQresultStatus(pgresult) == PGRES_FATAL_ERROR)
    {
      VINK_set_error("PostgreSQL query failed: %s", PQerrorMessage(pg));

      PQclear(pgresult);
      pgresult = 0;

      return -1;
    }

  tuple_count = PQntuples(pgresult);
  rowsaffected = strtol(PQcmdTuples(pgresult), 0, 0);

  return rowsaffected;
}
