#ifndef TERM_H_
#define TERM_H_ 1

#include <wchar.h>

#define TERM_DEFAULT   0x8000
#define TERM_FG_BLACK  0x0000
#define TERM_FG_BLUE   0x0001
#define TERM_FG_GREEN  0x0002
#define TERM_FG_RED    0x0004
#define TERM_BG_BLACK  0x0000
#define TERM_BG_BLUE   0x0010
#define TERM_BG_GREEN  0x0020
#define TERM_BG_RED    0x0040
#define TERM_STANDOUT  0x0100
#define TERM_UNDERLINE 0x0200

#define TERM_FG_CYAN      (TERM_FG_BLUE |  TERM_FG_GREEN)
#define TERM_FG_MAGENTA   (TERM_FG_BLUE |  TERM_FG_RED)
#define TERM_FG_YELLOW    (TERM_FG_GREEN | TERM_FG_RED)
#define TERM_FG_WHITE     (TERM_FG_BLUE |  TERM_FG_GREEN | TERM_FG_RED)
#define TERM_BG_CYAN      (TERM_BG_BLUE |  TERM_BG_GREEN)
#define TERM_BG_MAGENTA   (TERM_BG_BLUE |  TERM_BG_RED)
#define TERM_BG_YELLOW    (TERM_BG_GREEN | TERM_BG_RED)
#define TERM_BG_WHITE     (TERM_BG_BLUE |  TERM_BG_GREEN | TERM_BG_RED)

#define TERM_KEY_UP      0x8001
#define TERM_KEY_DOWN    0x8002
#define TERM_KEY_LEFT    0x8003
#define TERM_KEY_RIGHT   0x8004
#define TERM_KEY_PPAGE   0x8005
#define TERM_KEY_NPAGE   0x8006
#define TERM_KEY_HOME    0x8007
#define TERM_KEY_END     0x8008
#define TERM_KEY_INSERT  0x8009
#define TERM_KEY_DELETE  0x800A
#define TERM_KEY_F(n)    (0x800B + (n))

#define TERM_MOD_ALT     0x80000000

/**
 * Initialize.
 */
void
term_init();

/**
 * Clean up.
 *
 * Called automatically through atexit() handler installed by term_init().  Does
 * nothing the second time if called twice.
 */
void
term_exit();

/**
 * Handle screen resize.
 *
 * Not invoked automatically.  Catch SIGWINCH and call this.
 */
void
term_resize();

/**
 * Update screen with contents of canvas.
 */
void
term_paint();

/**
 * Clear screen, then update with contents of canvas.
 */
void
term_full_repaint();

/**
 * Clear canvas contents.
 */
void
term_clear();

/**
 * Add string to canvas.
 */
void
term_addstring(unsigned int attr, int x, int y, const wchar_t* text);

void
term_addstring_utf8(unsigned int attr, int x, int y, const unsigned char* text);

/**
 * Useful if you want to launch some external program.
 *
 * Restores canvas contents on screen when calling term_enable.
 */
void
term_disable();

/**
 * The opposite of term_disable().
 */
void
term_enable();

wchar_t
term_getc();

void
term_get_size(int* width, int* height);

#endif /* TERM_H_ */
