#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include <err.h>

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
};

static ARRAY(struct window) windows;
static size_t current_window;

static void
do_log(struct window *w, const wchar_t *format)
{
  while(*format)
    {
      w->log[w->log_cursor++] = *format;
      w->log_cursor %= w->log_size;
    }

  w->log[w->log_cursor++] = '\n';
  w->log_cursor %= w->log_size;
}

static void
init_windows()
{
  struct window status;

  status.name = wcsdup(L"status");
  status.log_size = 1000000;
  status.log = calloc(sizeof(*status.log), status.log_size);
  status.log_cursor = 0;

  do_log(&status, L"Started");

  ARRAY_ADD(&windows, status);

}

int
main(int argc, char **argv)
{
  char *config_path;
  wchar_t ch;
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

  if(!(config_path = getenv("HOME")))
    errx(EXIT_FAILURE, "HOME environment variable is not set");

  if(-1 == asprintf(&config_path, "%s/.config/vink/vink.conf", config_path))
    err(EXIT_FAILURE, "asprintf failed");

  vink_init(config_path, VINK_API_VERSION);
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
      unsigned int j;

      term_get_size(&width, &height);

      line = malloc(sizeof(*line) * (width + 1));

      w = &ARRAY_GET(&windows, current_window);

      for(i = 0; i < width; ++i)
        line[i] = ' ';
      line[width] = 0;

      term_addstring(TERM_BG_BLUE | TERM_FG_WHITE, 0, 0, line);

      line_end = w->log_cursor;

      while(w->log[line_end] == '\n')
        {
          fprintf(stderr, "line_end=%zu\n", line_end);
          line_begin = (line_end + w->log_size - 1) % w->log_size;

          while(w->log[line_begin]
                && w->log[line_begin] != '\n'
                && line_begin != w->log_cursor)
            line_begin = (line_begin + w->log_size - 1) % w->log_size;

          if(!line_begin || line_begin == w->log_cursor)
            break;

          for(j = 0, i = line_begin; i != line_end; i = (i + 1) % w->log_size)
            line[j++] = w->log[i];
          line[j] = 0;

          term_addstring(TERM_BG_BLACK | TERM_FG_WHITE, 0, 2, line);

          line_end = line_begin;
        }

      term_addstring(TERM_BG_BLUE | TERM_FG_WHITE, 0, height - 2, line);

      i = 0;
      line[i++] = '[';
      in = w->name;
      while(*in)
        line[i++] = *in++;
      line[i++] = ']';
      line[i++] = ' ';
      line[i] = 0;

      term_addstring(TERM_BG_BLACK | TERM_FG_WHITE, 0, height - 1, line);

      term_paint();

      if(EOF == (ch = term_getc()))
        break;
    }

  term_exit();

  return EXIT_SUCCESS;
}
