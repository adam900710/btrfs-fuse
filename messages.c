#include <stdio.h>
#include <stdarg.h>
#include "messages.h"

__attribute__ ((format (printf, 1, 2)))
void error(const char *fmt, ...)
{
	va_list args;

	fputs("ERROR: ", stderr);
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fputc('\n', stderr);
}

__attribute__ ((format (printf, 1, 2)))
void warning(const char *fmt, ...)
{
	va_list args;

	fputs("WARNING: ", stderr);
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fputc('\n', stderr);
}

__attribute__ ((format (printf, 1, 2)))
void info(const char *fmt, ...)
{
	va_list args;

	fputs("INFO: ", stdout);
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	putchar('\n');
}

__attribute__ ((format (printf, 1, 2)))
void debug(const char *fmt, ...)
{
#ifdef DEBUG
	va_list args;

	fputs("DEBUG: ", stdout);
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	putchar('\n');
#endif
}
