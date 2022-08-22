// #include "kb.h"

// void init_keyboard()
// {
//     tcgetattr(0, &initial_settings);
//     new_settings = initial_settings;
//     new_settings.c_lflag &= ~ICANON;
//     new_settings.c_lflag &= ~ECHO;
//     new_settings.c_cc[VMIN] = 1;
//     new_settings.c_cc[VTIME] = 0;
//     tcsetattr(0, TCSANOW, &new_settings);
// }

// void close_keyboard()
// {
//     tcsetattr(0, TCSANOW, &initial_settings);
// }

// int _kbhit()
// {
//     unsigned char ch;
//     int nread;

//     if (peek_character != -1)
//         return 1;
//     new_settings.c_cc[VMIN] = 0;
//     tcsetattr(0, TCSANOW, &new_settings);
//     nread = read(0, &ch, 1);
//     new_settings.c_cc[VMIN] = 1;
//     tcsetattr(0, TCSANOW, &new_settings);
//     if (nread == 1)
//     {
//         peek_character = ch;
//         return 1;
//     }
//     return 0;
// }

#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
int kbhit(void)
{
    struct termios oldt, newt;
    int ch;
    int oldf;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fcntl(STDIN_FILENO, F_SETFL, oldf);
    if (ch != EOF)
    {
        ungetc(ch, stdin);
        return 1;
    }
    return 0;
}
