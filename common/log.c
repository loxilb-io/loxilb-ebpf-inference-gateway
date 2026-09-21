/*
 * Copyright (c) 2020 rxi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "log.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define MAX_CALLBACKS 32

typedef struct {
  log_LogFn fn;
  void *udata;
  int level;
} Callback;

static struct {
  void *udata;
  log_LockFn lock;
  int level;
  bool quiet;
  Callback callbacks[MAX_CALLBACKS];
} L;


static const char *level_strings[] = {
  "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};



/* Each line is formatted once, in log_log, into a stack buffer; the sinks then
 * issue exactly one write(2) per line. The previous shape was three fprintf()
 * plus a vfprintf() on unbuffered stderr (three to four writes and as many
 * stdio lock round trips per line), and the same again plus fflush() for the
 * file sink; under load every proxy worker serialised on those. A single
 * write() to a file description is not interleaved with another thread's
 * write(), so the sinks need no lock of their own. */
#define LOG_LINE_MAX 4096
#define LOG_DATE_LEN 11          /* "YYYY-MM-DD " — the stderr copy skips it */

static void write_all(int fd, const char *buf, size_t len) {
  while (len > 0) {
    ssize_t n = write(fd, buf, len);
    if (n < 0) {
      if (errno == EINTR) continue;
      return;                    /* a sink that fails is not worth blocking on */
    }
    buf += n; len -= (size_t)n;
  }
}

static void stdout_callback(log_Event *ev) {
  /* stderr keeps its historical "HH:MM:SS LEVEL file:line: msg" shape */
  write_all(STDERR_FILENO, ev->line_buf + LOG_DATE_LEN, ev->line_len - LOG_DATE_LEN);
}


static void file_callback(log_Event *ev) {
  FILE *fp = ev->udata;
  if (!fp) return;
  fflush(fp);                    /* anything an earlier stdio user left behind */
  write_all(fileno(fp), ev->line_buf, ev->line_len);
}


static void lock(void)   {
  if (L.lock) { L.lock(true, L.udata); }
}


static void unlock(void) {
  if (L.lock) { L.lock(false, L.udata); }
}


const char* log_level_string(int level) {
  return level_strings[level];
}


void log_set_lock(log_LockFn fn, void *udata) {
  L.lock = fn;
  L.udata = udata;
}


void log_set_level(int level) {
  L.level = level;
}


void log_set_quiet(bool enable) {
  L.quiet = enable;
}


int log_add_callback(log_LogFn fn, void *udata, int level) {
  for (int i = 0; i < MAX_CALLBACKS; i++) {
    if (L.callbacks[i].fn && L.callbacks[i].udata == udata) {
      L.callbacks[i].level = level; 
      return 0;
    }
  }
  for (int i = 0; i < MAX_CALLBACKS; i++) {
    if (!L.callbacks[i].fn) {
      L.callbacks[i] = (Callback) { fn, udata, level };
      return 0;
    }
  }
  return -1;
}


int log_add_fp(FILE *fp, int level) {
  return log_add_callback(file_callback, fp, level);
}


static void init_event(log_Event *ev, void *udata) {
  ev->udata = udata;
}


/* Format the whole line once: "YYYY-MM-DD HH:MM:SS LEVEL file:line: msg\n".
 * Returns the length; a message longer than the buffer is truncated, the
 * newline is always the last byte. */
static size_t format_line(log_Event *ev, char *buf, size_t cap, va_list ap) {
  size_t n = strftime(buf, cap, "%Y-%m-%d %H:%M:%S", ev->time);
  int m = snprintf(buf + n, cap - n, " %-5s %s:%d: ",
                   level_strings[ev->level], ev->file, ev->line);
  if (m > 0) n += (size_t)m;
  if (n > cap - 2) n = cap - 2;
  m = vsnprintf(buf + n, cap - 1 - n, ev->fmt, ap);
  if (m > 0) n += (size_t)m;
  if (n > cap - 2) n = cap - 2;
  if (n > 0 && buf[n - 1] == '\n') n--;   /* one newline, even if the format carried its own */
  buf[n++] = '\n';
  buf[n] = '\0';
  return n;
}


void log_log(int level, const char *file, int line, const char *fmt, ...) {
  log_Event ev = {
    .fmt   = fmt,
    .file  = file,
    .line  = line,
    .level = level,
  };
  char buf[LOG_LINE_MAX];
  struct tm tm;
  time_t t;
  int i, wanted = 0;

  /* Cheap early-out: nothing is formatted, and no lock is taken, for a line
   * below every sink's level (the common case for log_debug at info). */
  if (!L.quiet && level >= L.level) wanted = 1;
  for (i = 0; i < MAX_CALLBACKS && L.callbacks[i].fn && !wanted; i++) {
    if (level >= L.callbacks[i].level) wanted = 1;
  }
  if (!wanted) return;

  t = time(NULL);
  ev.time = localtime_r(&t, &tm);
  va_start(ev.ap, fmt);
  ev.line_len = format_line(&ev, buf, sizeof(buf), ev.ap);
  va_end(ev.ap);
  ev.line_buf = buf;

  lock();

  if (!L.quiet && level >= L.level) {
    init_event(&ev, stderr);
    stdout_callback(&ev);
  }

  for (i = 0; i < MAX_CALLBACKS && L.callbacks[i].fn; i++) {
    Callback *cb = &L.callbacks[i];
    if (level >= cb->level) {
      init_event(&ev, cb->udata);
      va_start(ev.ap, fmt);     /* an external callback may still format ev->fmt itself */
      cb->fn(&ev);
      va_end(ev.ap);
    }
  }

  unlock();
}
