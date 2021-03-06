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
#include "vink-internal.h"
#include "vink-tree.h"

static PGconn *pg; /* Database connection handle */
static PGresult *pgresult;
static int tuple_count;
static char *last_sql;

static int
sql_exec (const char *query, ...);

static void
sql_free_result ();

#define sql_value(i, j) PQgetvalue (pgresult, (i), (j))

static int
xmpp_authenticate (const char *authzid, const char *user, const char *secret)
{
  const char *domain;
  int result = 0;

  domain = vink_config ("domain");

  sql_exec ("SELECT password FROM users WHERE domain = %s AND username = %s",
            domain, user);

  if (!tuple_count || strcmp (secret, sql_value (0, 0)))
    result = -1;

  sql_free_result ();

  return result;
}

static void
email_message (struct vink_message *message)
{
  int result;

  result = sql_exec ("INSERT INTO messages "
                     "(id, protocol, part_type, sent, received, content_type, sender, "
                     "receiver, subject, body) "
                     "VALUES "
                     "(%s, %u, %u, %l, %l, %s, %s, %s, %s, %s)",
                     message->id, message->protocol, message->part_type,
                     (unsigned long long) message->sent,
                     (unsigned long long) message->received,
                     message->content_type, message->from, message->to, message->subject,
                     message->body);

  if (result == -1)
    fprintf (stderr, "Error: %s\n", vink_last_error ());

  vink_message_free (message);
}

static void
xmpp_message (struct vink_xmpp_state *state, struct vink_message *message)
{
  email_message (message);
}

static void
xmpp_presence (struct vink_xmpp_state *state, const char *jid,
               enum vink_presence presence)
{
  fprintf (stderr, "Got presence for %s\n", jid);
}

static void
xmpp_queue_empty (struct vink_xmpp_state *state)
{
  fprintf (stderr, "Queue is empty\n");
}

static void
list_messages(const char *jid,
              int (*callback)(struct vink_message *msg),
              size_t offset, size_t limit)
{
  int i;

  if (-1 == sql_exec ("SELECT id, protocol, part_type, sent, received,"
                      "       content_type, sender, receiver, subject, body"
                      "  FROM messages"
                      "  ORDER BY seqid"
                      "  LIMIT %zu"
                      "  OFFSET %zu",
                      offset, limit))
    {
      errx (EXIT_FAILURE, "Failed to read \"messages\" table: %s",
            PQerrorMessage (pg));
    }

  for (i = 0; i < tuple_count; ++i)
    {
      struct vink_message msg;

      memset (&msg, 0, sizeof (msg));

      msg.id = sql_value(i, 0);

      msg.protocol = atoi (sql_value(i, 1));
      msg.part_type = atoi (sql_value(i, 2));

      msg.sent = strtoll (sql_value(i, 3), 0, 0);
      msg.received = strtoll (sql_value(i, 4), 0, 0);

      msg.content_type = sql_value(i, 5);

      msg.from = sql_value(i, 6);
      msg.to = sql_value(i, 7);
      msg.subject = sql_value(i, 8);
      msg.body = sql_value(i, 9);
      msg.body_size = PQgetlength(pgresult, i, 9);

      callback (&msg);
    }
}

void
backend_postgresql_init (struct vink_backend_callbacks *callbacks)
{
  char *connect_string;

  callbacks->xmpp.authenticate = xmpp_authenticate;
  callbacks->xmpp.message = xmpp_message;
  callbacks->xmpp.presence = xmpp_presence;
  callbacks->xmpp.queue_empty = xmpp_queue_empty;
  callbacks->email.message = email_message;
  callbacks->list_messages = list_messages;

  if (-1 == asprintf (&connect_string,
                      "dbname=%s user=%s password=%s host=%s port=%u",
                      vink_tree_get_string (VINK_config, "backend.database"),
                      vink_tree_get_string (VINK_config, "backend.user"),
                      vink_tree_get_string (VINK_config, "backend.password"),
                      vink_tree_get_string (VINK_config, "backend.host"),
                      (unsigned int) vink_tree_get_integer (VINK_config, "backend.port")))
    err (EXIT_FAILURE, "asprintf failed\n");

  pg = PQconnectdb (connect_string);

  free (connect_string);

  if (PQstatus (pg) != CONNECTION_OK)
    errx (EXIT_FAILURE, "PostgreSQL connection failed: %s", PQerrorMessage (pg));

  if (-1 == sql_exec ("SET SEARCH_PATH TO vink"))
    errx (EXIT_FAILURE, "Failed to select 'vink' schema: %s", vink_last_error());

  sql_exec ("SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE");
}

static void
sql_free_result ()
{
  if (pgresult)
    {
      PQclear (pgresult);
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
sql_exec (const char *query, ...)
{
  static char numbufs[10][128];
  const char *args[10];
  int lengths[10];
  int formats[10];
  const char *c;
  int argcount = 0;
  va_list ap;
  int rowsaffected, is_size_t = 0;

  ARRAY (char) new_query;

  if (pgresult)
    {
      PQclear (pgresult);
      pgresult = 0;
    }

  va_start (ap, query);

  ARRAY_INIT (&new_query);

  for (c = query; *c; )
    {
      switch (*c)
        {
        case '%':

          is_size_t = 0;

          ++c;

          if (*c == 'z')
            {
              is_size_t = 1;
              ++c;
            }

          switch (*c)
            {
            case 's':

              args[argcount] = va_arg (ap, const char*);
              lengths[argcount] = strlen(args[argcount]);
              formats[argcount] = 0;

              break;

            case 'd':

              snprintf (numbufs[argcount], 127, "%d", va_arg (ap, int));
              args[argcount] = numbufs[argcount];
              lengths[argcount] = strlen(args[argcount]);
              formats[argcount] = 0;

              break;

            case 'u':

              if (is_size_t)
                snprintf (numbufs[argcount], 127, "%zu", va_arg (ap, size_t));
              else
                snprintf (numbufs[argcount], 127, "%u", va_arg (ap, unsigned int));
              args[argcount] = numbufs[argcount];
              lengths[argcount] = strlen(args[argcount]);
              formats[argcount] = 0;

              break;

            case 'l':

              snprintf (numbufs[argcount], 127, "%lld", va_arg (ap, long long));
              args[argcount] = numbufs[argcount];
              lengths[argcount] = strlen(args[argcount]);
              formats[argcount] = 0;

              break;

            case 'f':

              snprintf (numbufs[argcount], 127, "%f", va_arg (ap, double));
              args[argcount] = numbufs[argcount];
              lengths[argcount] = strlen(args[argcount]);
              formats[argcount] = 0;

              break;

            case 'B':

              args[argcount] = va_arg (ap, const char *);
              lengths[argcount] = va_arg (ap, size_t);
              formats[argcount] = 1;

              break;

            default:

              assert (!"unknown format character");

              return -1;
            }

          ++c;
          ++argcount;

          ARRAY_ADD (&new_query, '$');
          if (argcount >= 10)
            ARRAY_ADD (&new_query, '0' + (argcount / 10));
          ARRAY_ADD (&new_query, '0' + (argcount % 10));

          break;

        default:

          ARRAY_ADD (&new_query, *c);
          ++c;
        }
    }

  va_end (ap);

  ARRAY_ADD (&new_query, 0);

  free (last_sql);
  last_sql = strdup (&ARRAY_GET (&new_query, 0));
  pgresult = PQexecParams (pg, last_sql, argcount, 0, args, lengths, formats, 0);

  if (PQresultStatus (pgresult) == PGRES_FATAL_ERROR)
    {
      VINK_set_error ("PostgreSQL query failed: %s", PQerrorMessage (pg));

      PQclear (pgresult);
      pgresult = 0;

      return -1;
    }

  tuple_count = PQntuples (pgresult);
  rowsaffected = strtol (PQcmdTuples (pgresult), 0, 0);

  return rowsaffected;
}
