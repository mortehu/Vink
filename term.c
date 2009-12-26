#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "term.h"

struct TERM_char
{
  unsigned int attr;
  wchar_t ch;
};

static int TERM_width, TERM_height;
static int TERM_curx, TERM_cury;
static int TERM_cursorx, TERM_cursory;
static unsigned int TERM_curattr;
static struct TERM_char* TERM_screen;
static struct TERM_char* TERM_canvas;

static struct termios TERM_orig_termios;
static struct termios TERM_termios;

static void TERM_setattr(unsigned int attr);

void
term_resize()
{
  struct winsize winsize;

  if(-1 == ioctl(STDIN_FILENO, TIOCGWINSZ, &winsize))
    {
      TERM_width = 80;
      TERM_height = 24;
    }
  else
    {
      if(winsize.ws_col == TERM_width && winsize.ws_row == TERM_height)
        return;

      TERM_width = winsize.ws_col;
      TERM_height = winsize.ws_row;
    }

  free(TERM_screen);
  free(TERM_canvas);

  TERM_screen = calloc(sizeof(struct TERM_char), TERM_width * TERM_height);
  TERM_canvas = calloc(sizeof(struct TERM_char), TERM_width * TERM_height);

  printf("\033[2J");
}

void
term_exit()
{
  if(TERM_screen)
    {
      tcsetattr(0, TCSANOW, &TERM_orig_termios);

      free(TERM_screen);
      free(TERM_canvas);
      TERM_screen = 0;
      TERM_canvas = 0;

      printf("\033[?1049l\033[00m");
      fflush(stdout);
    }
}

void
term_init()
{
  if(TERM_screen)
    return;

  tcgetattr(0, &TERM_orig_termios);
  TERM_termios = TERM_orig_termios;
  TERM_termios.c_lflag = 0;
  tcsetattr(0, TCSANOW, &TERM_termios);

  term_resize();

  TERM_curx = 0;
  TERM_cury = 0;
  TERM_curattr = TERM_FG_WHITE | TERM_BG_BLACK;

  printf("\033[?1049h\033[0;0H\033[00;37;40m");

  atexit(term_exit);
}

static void
TERM_moveto(int x, int y)
{
  if(TERM_curx == x && TERM_cury == y)
    return;

  if(TERM_curx == x + 1)
    {
      putchar('\b');
      --TERM_curx;

      if(TERM_curx == x && TERM_cury == y)
        return;
    }

  if(TERM_curx == x && TERM_cury > y)
    {
      if(TERM_cury == y + 1)
        printf("\033[A");
      else
        printf("\033[%dA", TERM_cury - y);
    }
  else if(TERM_curx == x && TERM_cury < y)
    {
      if(TERM_cury + 1 == y)
        printf("\033[B");
      else
        printf("\033[%dB", y - TERM_cury);
    }
  else
    printf("\033[%d;%dH", y + 1, x + 1);

  TERM_curx = x;
  TERM_cury = y;
}

static void
TERM_setattr(unsigned int attr)
{
  char command[16];
  int first = 1;

  if(attr == TERM_curattr)
    return;

  strcpy(command, "\033[");

  if((attr ^ TERM_curattr) & 0x0f)
    {
      switch(attr & 0x0f)
        {
        case TERM_FG_BLACK: strcat(command, "30"); break;
        case TERM_FG_RED: strcat(command, "31"); break;
        case TERM_FG_GREEN: strcat(command, "32"); break;
        case TERM_FG_YELLOW: strcat(command, "33"); break;
        case TERM_FG_BLUE: strcat(command, "34"); break;
        case TERM_FG_MAGENTA: strcat(command, "35"); break;
        case TERM_FG_CYAN: strcat(command, "36"); break;
        case TERM_FG_WHITE: strcat(command, "37"); break;
        }

      first = 0;
    }

  if((attr ^ TERM_curattr) & 0xf0)
    {
      if(!first)
        strcat(command, ";");

      switch(attr & 0xf0)
        {
        case TERM_BG_BLACK: strcat(command, "40"); break;
        case TERM_BG_RED: strcat(command, "41"); break;
        case TERM_BG_GREEN: strcat(command, "42"); break;
        case TERM_BG_YELLOW: strcat(command, "43"); break;
        case TERM_BG_BLUE: strcat(command, "44"); break;
        case TERM_BG_MAGENTA: strcat(command, "45"); break;
        case TERM_BG_CYAN: strcat(command, "46"); break;
        case TERM_BG_WHITE: strcat(command, "47"); break;
        }

      first = 0;
    }

  if((attr ^ TERM_curattr) & TERM_STANDOUT)
    {
      if(!first)
        strcat(command, ";");

      if(attr & TERM_STANDOUT)
        strcat(command, "1");
      else
        strcat(command, "22");

      first = 0;
    }

  if((attr ^ TERM_curattr) & TERM_UNDERLINE)
    {
      if(!first)
        strcat(command, ";");

      if(attr & TERM_UNDERLINE)
        strcat(command, "4");
      else
        strcat(command, "24");
    }

  strcat(command, "m");

  fwrite(command, 1, strlen(command), stdout);

  TERM_curattr = attr;
}

void
term_paint()
{
  int x, y, i, j;
  int c, cwidth;

  for(y = 0, i = 0; y < TERM_height; ++y)
    {
      for(x = 0; x < TERM_width; ++x, ++i)
        {
          if(memcmp(&TERM_screen[i], &TERM_canvas[i], sizeof(struct TERM_char)))
            {
              TERM_moveto(x, y);

              if(TERM_canvas[i].attr != TERM_curattr)
                TERM_setattr(TERM_canvas[i].attr);

              if(TERM_canvas[i].ch)
                {
                  c = TERM_canvas[i].ch;
                  cwidth = wcwidth(TERM_canvas[i].ch);

                  if(c < 0x80)
                    putchar(c);
                  else if(c < 0x800)
                    {
                      putchar(0xc0 | (c >> 6));
                      putchar(0x80 | (c & 0x3f));
                    }
                  else if(c < 0x10000)
                    {
                      putchar(0xe0 | (c >> 12));
                      putchar(0x80 | ((c >> 6) & 0x3f));
                      putchar(0x80 | (c & 0x3f));
                    }
                  else if(c < 0x200000)
                    {
                      putchar(0xf0 | (c >> 18));
                      putchar(0x80 | ((c >> 12) & 0x3f));
                      putchar(0x80 | ((c >> 6) & 0x3f));
                      putchar(0x80 | (c & 0x3f));
                    }
                  else if(c < 0x4000000)
                    {
                      putchar(0xf8 | (c >> 24));
                      putchar(0x80 | ((c >> 18) & 0x3f));
                      putchar(0x80 | ((c >> 12) & 0x3f));
                      putchar(0x80 | ((c >> 6) & 0x3f));
                      putchar(0x80 | (c & 0x3f));
                    }
                  else
                    {
                      putchar(0xfc | (c >> 30));
                      putchar(0x80 | ((c >> 24) & 0x3f));
                      putchar(0x80 | ((c >> 18) & 0x3f));
                      putchar(0x80 | ((c >> 12) & 0x3f));
                      putchar(0x80 | ((c >> 6) & 0x3f));
                      putchar(0x80 | (c & 0x3f));
                    }

                  for(j = 1; j < cwidth; ++j)
                    {
                      TERM_screen[y * TERM_width + x + j].attr = TERM_canvas[i].attr;
                      TERM_screen[y * TERM_width + x + j].ch = 0;
                    }

                  TERM_curx += cwidth;
                }
              else
                {
                  putchar(' ');
                  ++TERM_curx;
                }

              if(TERM_curx >= TERM_width)
                {
                  TERM_curx = 0;
                  ++TERM_cury;
                }

              TERM_screen[i] = TERM_canvas[i];
            }
        }
    }

  TERM_moveto(TERM_cursorx, TERM_cursory);

  fflush(stdout);
}

void
term_full_repaint()
{
  if(!TERM_screen)
    return;

  memset(TERM_screen, 0xff, sizeof(struct TERM_char) * TERM_width * TERM_height);

  TERM_curx = 0;
  TERM_cury = 0;
  TERM_curattr = TERM_FG_WHITE | TERM_BG_BLACK;

  printf("\033[?1049h\033[0;0H\033[00;37;40m");

  term_paint();
}

void
term_clear()
{
  if(!TERM_screen)
    return;

  memset(TERM_canvas, 0, sizeof(struct TERM_char) * TERM_width * TERM_height);
}

void
term_addstring(unsigned int attr, int x, int y, const wchar_t* text)
{
  int cwidth, i;

  if(!TERM_screen)
    return;

  if(y < 0 || y >= TERM_height)
    return;

  while(x < 0 && *text)
    x += wcwidth(*text++);

  if(x < 0)
    return;

  while(x < TERM_width && *text)
    {
      cwidth = wcwidth(*text);

      if(cwidth)
        {
          TERM_canvas[y * TERM_width + x].attr = attr;
          TERM_canvas[y * TERM_width + x].ch = *text;

          for(i = 1; i < cwidth; ++i)
            {
              TERM_canvas[y * TERM_width + x].attr = attr;
              TERM_canvas[y * TERM_width + x].ch = 0;
            }

          x += cwidth;
        }

      ++text;
    }

  TERM_cursorx = x;
  TERM_cursory = y;
}

void
term_addstring_utf8(unsigned int attr, int x, int y, const unsigned char* text)
{
  int cwidth, i;

  if(!TERM_screen)
    return;

  if(y < 0 || y >= TERM_height)
    return;

  if(x < 0)
    return;

  while(x < TERM_width && *text)
    {
      int ch = 0;
      int n;

      /* Check for invalid UTF-8 */
      if((*text & 0xC0) == 0x80)
        return;

      ch = *text++;

      if(ch & 0x80)
        {
          if((ch & 0xE0) == 0xC0)
            {
              ch &= 0x1F;

              n = 1;
            }
          else if((ch & 0xF0) == 0xE0)
            {
              ch &= 0x0F;

              n = 2;
            }
          else if((ch & 0xF8) == 0xF0)
            {
              ch &= 0x07;

              n = 3;
            }
          else if((ch & 0xFC) == 0xF8)
            {
              ch &= 0x03;

              n = 4;
            }
          else if((ch & 0xFE) == 0xFC)
            {
              ch &= 0x01;

              n = 5;
            }
          else
            return;

          while(n--)
            {
              if(!*text)
                return;

              int b = (unsigned char) *text;

              if((b & 0xC0) != 0x80)
                return;

              ch <<= 6;
              ch |= (b & 0x3F);

              ++text;
            }
        }

      switch(ch)
        {
        case '\t':

          x = (x + 8) & ~7;

          break;

        default:

          cwidth = wcwidth(ch);

          if(cwidth)
            {
              TERM_canvas[y * TERM_width + x].attr = attr;
              TERM_canvas[y * TERM_width + x].ch = ch;

              for(i = 1; i < cwidth; ++i)
                {
                  TERM_canvas[y * TERM_width + x].attr = attr;
                  TERM_canvas[y * TERM_width + x].ch = 0;
                }

              x += cwidth;
            }
        }
    }

  TERM_cursorx = x;
  TERM_cursory = y;
}

void
term_disable()
{
  printf("\033[?1049l");
  fflush(stdout);
  tcsetattr(0, TCSANOW, &TERM_orig_termios);
}

void
term_enable()
{
  tcsetattr(0, TCSANOW, &TERM_termios);

  TERM_curx = 0;
  TERM_cury = 0;
  TERM_curattr = TERM_FG_WHITE | TERM_BG_BLACK;

  printf("\033[?1049h\033[0;0H\033[00;37;40m");

  term_full_repaint();
}

wchar_t
term_getc()
{
  static wchar_t queue[4];
  static wchar_t queuelen;
  int result;
  int newqueuelen = 0;

  /* XXX: this could easily be nicer */

  if(queuelen)
    {
      result = queue[0];
      --queuelen;
      memmove(&queue[0], &queue[1], queuelen * sizeof(wchar_t));

      return result;
    }

  result = getchar();

  if(result & 0x80)
    {
      int n; /* Number of following bytes */

      if((result & 0xE0) == 0xC0)
        {
          result &= 0x1F;

          n = 1;
        }
      else if((result & 0xF0) == 0xE0)
        {
          result &= 0x0F;

          n = 2;
        }
      else if((result & 0xF8) == 0xF0)
        {
          result &= 0x07;

          n = 3;
        }
      else if((result & 0xFC) == 0xF8)
        {
          result &= 0x03;

          n = 4;
        }
      else if((result & 0xFE) == 0xFC)
        {
          result &= 0x01;

          n = 5;
        }
      else
        {
          result = '?';

          n = 0;
        }

      while(n--)
        {
          int b;

          b = getchar();

          if((b & 0xC0) != 0x80)
            {
              result = '?';

              break;
            }

          result <<= 6;
          result |= (b & 0x3F);
        }
    }

  switch(result)
    {
    case '\033':

      queue[newqueuelen++] = getchar();

      if(queue[0] == 'O' || queue[0] == '[')
        {
          int arg = 0;
          int double_bracket = 0;
          int ch;

          ch = getchar();

          if(ch == '[')
            {
              double_bracket = 1;
              ch = getchar();
            }

          while(isdigit(ch))
            {
              if(!isdigit(ch))
                break;

              arg *= 10;
              arg += ch - '0';

              ch = getchar();
            }

          /* Common for O and [ */
          switch(ch)
            {
            case 'H': return TERM_KEY_HOME;
            case 'F': return TERM_KEY_END;
            }

          if(queue[0] == 'O')
            {
              switch(ch)
                {
                case 'P': return TERM_KEY_F(1);
                case 'Q': return TERM_KEY_F(2);
                case 'R': return TERM_KEY_F(3);
                case 'S': return TERM_KEY_F(4);
                }
            }
          else if(double_bracket)
            {
              switch(ch)
                {
                case 'A': return TERM_KEY_F(1);
                case 'B': return TERM_KEY_F(2);
                case 'C': return TERM_KEY_F(3);
                case 'D': return TERM_KEY_F(4);
                case 'E': return TERM_KEY_F(5);
                }
            }
          else /* queue[0] == '[' */
            {
              switch(ch)
                {
                case 'A': return TERM_KEY_UP;
                case 'B': return TERM_KEY_DOWN;
                case 'C': return TERM_KEY_RIGHT;
                case 'D': return TERM_KEY_LEFT;
                case '~':

                          switch(arg)
                            {
                            case 1: return TERM_KEY_HOME;
                            case 2: return TERM_KEY_INSERT;
                            case 3: return TERM_KEY_DELETE;
                            case 4: return TERM_KEY_END;
                            case 5: return TERM_KEY_PPAGE;
                            case 6: return TERM_KEY_NPAGE;
                            case 15: return TERM_KEY_F(5);
                            case 17: return TERM_KEY_F(6);
                            case 18: return TERM_KEY_F(7);
                            case 19: return TERM_KEY_F(8);
                            case 20: return TERM_KEY_F(9);
                            case 21: return TERM_KEY_F(10);
                            case 23: return TERM_KEY_F(11);
                            case 24: return TERM_KEY_F(12);
                            }
                }
            }
        }
      else
        return queue[0] | TERM_MOD_ALT;

      break;

    case '\n': return '\r';
    }

  queuelen = newqueuelen;

  return result;
}

void
term_get_size(int* width, int* height)
{
  if(width)
    *width = TERM_width;

  if(height)
    *height = TERM_height;
}
