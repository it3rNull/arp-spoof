#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <termios.h>

static struct termios initial_settings, new_settings;

static int peek_character = -1;

void init_keyboard();

void close_keyboard();

int _kbhit();

int _getch();