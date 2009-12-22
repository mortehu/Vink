#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <signal.h>
#include <sysexits.h>
#include <sys/time.h>
#include <time.h>

#include "array.h"
#include "term.h"
#include "vink.h"

static int print_version;
static int print_help;

static struct option long_options[] =
{
  { "recipient",      required_argument, 0, 'r' },
  { "version",        no_argument, &print_version, 1 },
  { "help",           no_argument, &print_help,    1 },
  { 0, 0, 0, 0 }
};

struct window
{
  wchar_t* name;
  wchar_t* log;
  size_t log_size;
  size_t log_cursor;
  int activity;
};

static ARRAY(struct window) windows;
static size_t current_window;

static void
do_log(struct window *w, const wchar_t *format, ...)
{
  time_t now;
  wchar_t *target, *c;
  size_t target_alloc;
  va_list args;
  int result;

  target_alloc = 256;
  target = malloc(sizeof(*target) * target_alloc);

  now = time(0);

  swprintf(target, target_alloc, L"%02u:%02u:%02u ",
           (unsigned int) (now / 60 / 60) % 24,
           (unsigned int) (now / 60) % 60,
           (unsigned int) (now % 60));

  c = target;

  while(*c)
    {
      w->log[w->log_cursor++] = *c++;
      w->log_cursor %= w->log_size;
    }

  for(;;)
    {
      va_start(args, format);
      result = vswprintf(target, target_alloc, format, args);
      va_end(args);

      if(result > -1 && result < target_alloc)
        break;

      if(result > -1)
        target_alloc = result + 1;
      else
        target_alloc *= 2;

      free(target);
      target = malloc(sizeof(*target) * target_alloc);
    }

  c = target;

  while(*c)
    {
      w->log[w->log_cursor++] = *c++;
      w->log_cursor %= w->log_size;
    }

  w->log[w->log_cursor++] = '\n';
  w->log_cursor %= w->log_size;
  w->activity = 1;
}

static void
init_windows()
{
  struct window status;

  status.name = wcsdup(L"status");
  status.log_size = 100000;
  status.log = calloc(sizeof(*status.log), status.log_size);
  status.log_cursor = 0;

  do_log(&status, L"Started");

  ARRAY_ADD(&windows, status);
}

static ARRAY(wchar_t) command;
static ARRAY(wchar_t) yank;

static void
do_quit(wchar_t *args)
{
  do_log(&ARRAY_GET(&windows, 0), L"Exited");

  exit(EXIT_SUCCESS);
}

const struct
{
  const wchar_t *name;
  size_t name_length;
  void (*action)(wchar_t *args);
} commands[] =
{
  { L"quit", 4, do_quit },
};

static void
send_message(wchar_t *command, size_t length)
{
  if(current_window == 0)
    do_log(&ARRAY_GET(&windows, 0), L"This is the status window.  You can't send messages here");
}

static void
do_command(wchar_t *command, size_t length)
{
  size_t i, command_length = 1;

  if(!length)
    return;

  if(command[0] != '/')
    {
      send_message(command, length);

      return;
    }

  while(command_length < length && !isspace(command[command_length]))
    ++command_length;

  ++command;
  --command_length;

  if(!command_length)
    return;

  for(i = 0; i < sizeof(commands) / sizeof(commands[0]); ++i)
    {
      if(commands[i].name_length == command_length
         && !memcmp(commands[i].name, command, sizeof(*command) * command_length))
        {
          commands[i].action(command + command_length);

          return;
        }
    }

  do_log(&ARRAY_GET(&windows, current_window), L"Invalid command '%.*ls'", (int) command_length, command);
}

static void
handle_char(int ch)
{
  static int yank_chain = 0;
  int reset_yank_chain = 1;
  size_t i, length;

  length = ARRAY_COUNT(&command);

  switch(ch)
  {
  case '\b':

    if(length)
      --ARRAY_COUNT(&command);

    break;

  case '\r':

    do_command(&ARRAY_GET(&command, 0), ARRAY_COUNT(&command));
    ARRAY_RESET(&command);

    break;

  case 'U' & 0x3F:

    ARRAY_RESET(&yank);
    ARRAY_ADD_SEVERAL(&yank, &ARRAY_GET(&command, 0), ARRAY_COUNT(&command));
    ARRAY_RESET(&command);

    break;

  case 'W' & 0x3F:

    reset_yank_chain = 0;

    if(!length)
      break;

    i = length - 1;

    while(i > 0 && isspace(ARRAY_GET(&command, i)))
      --i;

    while(i > 0 && !isspace(ARRAY_GET(&command, i - 1)))
      --i;

    if(yank_chain)
      ARRAY_INSERT_SEVERAL(&yank, 0, &ARRAY_GET(&command, i), ARRAY_COUNT(&command) - i);
    else
      {
        ARRAY_RESET(&yank);
        ARRAY_ADD_SEVERAL(&yank, &ARRAY_GET(&command, i), ARRAY_COUNT(&command) - i);
      }

    ARRAY_COUNT(&command) = i;

    yank_chain = 1;

    break;

  case 'Y' & 0x3F:

    ARRAY_ADD_SEVERAL(&command, &ARRAY_GET(&yank, 0), ARRAY_COUNT(&yank));

    break;

  default:

    ARRAY_ADD(&command, ch);
  }

  if(reset_yank_chain)
    yank_chain = 0;
}

static void
sighandler(int signal)
{
  term_exit();

  exit(EXIT_SUCCESS);
}

static void
make_status_line(wchar_t* target, int width)
{
  time_t now;

  target[0] = 0;

  if(width < 10)
     return;

  ARRAY_GET(&windows, current_window).activity = 0;

  now = time(0);

  swprintf(target, 10, L" %02u:%02u:%02u ",
           (unsigned int) (now / 60 / 60) % 24,
           (unsigned int) (now / 60) % 60,
           (unsigned int) (now % 60));
}

static void
handle_key()
{
  fd_set readset;
  int result;
  struct timeval timeout;

  FD_ZERO(&readset);
  FD_SET(0, &readset);

  gettimeofday(&timeout, 0);
  timeout.tv_sec = 0;
  timeout.tv_usec = 1000000 - timeout.tv_usec;

  result = select(1, &readset, 0, 0, &timeout);

  if(result == -1)
    {
      if(errno != EINTR)
        err(EX_OSERR, "select failed");

      return;
    }

  if(!FD_ISSET(0, &readset))
    return;

  handle_char(term_getc());
}

int
main(int argc, char **argv)
{
  char *config_path;
  int i;

  while((i = getopt_long(argc, argv, "", long_options, 0)) != -1)
    {
      switch(i)
        {
        case 0:

          break;

        case '?':

          fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);

          return EXIT_FAILURE;
        }
    }

  if(print_help)
    {
      printf("Usage: %s [OPTION]...\n"
             "\n"
             "      --help     display this help and exit\n"
             "      --version  display version information\n"
             "\n"
             "Report bugs to <morten@rashbox.org>\n", argv[0]);

      return EXIT_SUCCESS;
    }

  if(print_version)
    {
      fprintf(stdout, "%s\n", PACKAGE_STRING);

      return EXIT_SUCCESS;
    }

  signal(SIGINT, sighandler);

  if(!(config_path = getenv("HOME")))
    errx(EXIT_FAILURE, "HOME environment variable is not set");

  if(-1 == asprintf(&config_path, "%s/.config/vink/vink.conf", config_path))
    err(EXIT_FAILURE, "asprintf failed");

  if(-1 == vink_init(config_path, VINK_CLIENT, VINK_API_VERSION))
    errx(EXIT_FAILURE, "vink_init failed: %s", vink_last_error());

  free(config_path);

  init_windows();

  term_init();

  for(;;)
    {
      struct window *w;
      wchar_t *line;
      const wchar_t *in;
      size_t line_begin, line_end;
      int width, height;
      unsigned int j, line_idx = 0;

      width = 80;
      height = 25;
      term_get_size(&width, &height);

      term_clear();

      line = malloc(sizeof(*line) * (width + 1));

      w = &ARRAY_GET(&windows, current_window);

      i = swprintf(line, width, L"%s - Report bugs to %s", PACKAGE_STRING, PACKAGE_BUGREPORT);
      while(i < width)
        line[i++] = ' ';
      line[i] = 0;

      term_addstring(TERM_BG_BLUE | TERM_FG_WHITE, 0, 0, line);

      line_end = (w->log_cursor + w->log_size - 1) % w->log_size;

      while(w->log[line_end] == '\n' && line_idx < height - 3)
        {
          line_begin = (line_end + w->log_size - 1) % w->log_size;

          while(w->log[line_begin]
                && w->log[line_begin] != '\n'
                && line_begin != w->log_cursor)
            line_begin = (line_begin + w->log_size - 1) % w->log_size;

          if(!line_begin || line_begin == w->log_cursor)
            break;

          for(j = 0, i = (line_begin + 1) % w->log_size; i != line_end; i = (i + 1) % w->log_size)
            line[j++] = w->log[i];
          line[j] = 0;

          term_addstring(TERM_BG_BLACK | TERM_FG_WHITE, 0, height - line_idx - 3, line);

          line_end = line_begin;
          ++line_idx;
        }

      i = 0;
      while(i < width)
        line[i++] = ' ';

      make_status_line(line, width);

      term_addstring(TERM_BG_BLUE | TERM_FG_WHITE, 0, height - 2, line);

      i = 0;
      line[i++] = '[';
      in = w->name;
      while(*in)
        line[i++] = *in++;
      line[i++] = ']';
      line[i++] = ' ';
      j = 0;

      while(i < width && j < ARRAY_COUNT(&command))
        line[i++] = ARRAY_GET(&command, j++);

      line[i] = 0;

      term_addstring(TERM_BG_BLACK | TERM_FG_WHITE, 0, height - 1, line);

      term_paint();

      handle_key();
    }

  term_exit();

  return EXIT_SUCCESS;
}
