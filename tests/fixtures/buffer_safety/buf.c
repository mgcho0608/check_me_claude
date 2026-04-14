/**
 * fixture: buffer_safety/buf.c
 *
 * Target scenario: Code Mode — BUFFER_OVERFLOW_RISK, FORMAT_STRING_RISK
 *
 * Structural candidates expected:
 *   - gets -> strcpy (unbounded copy)
 *   - fgets -> sprintf (format risk)
 */

#include <stdio.h>
#include <string.h>

char g_buf[256];

/* ── source functions ── */
int read_input(char *buf, int maxlen) {
    return fgets(buf, maxlen, stdin) ? 0 : -1;
}

/* ── bad: unbounded copy after external read ── */
void process_input_bad(void) {
    char tmp[64];
    gets(tmp);            /* source: gets */
    strcpy(g_buf, tmp);  /* sink: strcpy — BUFFER_OVERFLOW_RISK candidate */
}

/* ── bad: format string via user-controlled data ── */
void log_input_bad(const char *user_input) {
    char msg[128];
    sprintf(msg, user_input);  /* sink: sprintf with user data — FORMAT_STRING_RISK */
    printf("%s\n", msg);
}

/* ── good: bounded copy ── */
void process_input_good(void) {
    char tmp[64];
    fgets(tmp, sizeof(tmp), stdin);
    strncpy(g_buf, tmp, sizeof(g_buf) - 1);  /* sanitizer: strncpy */
    g_buf[sizeof(g_buf) - 1] = '\0';
}

/* ── good: safe format ── */
void log_input_good(const char *user_input) {
    char msg[128];
    snprintf(msg, sizeof(msg), "%s", user_input);  /* sanitizer: snprintf */
    printf("%s\n", msg);
}
