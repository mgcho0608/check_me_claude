/**
 * fixture: auth_session/auth.c
 *
 * Target scenario: auth_session_replay_state
 *
 * Structural candidates expected:
 *   - admin_action without authenticated state check
 *   - session persisted without invalidation path (replay risk)
 *   - grant_permission called on stale session
 */

#include <stdbool.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    char     user_id[64];
    uint32_t token;
    bool     authenticated;
    bool     expired;
} Session;

static Session current_session;

/* ── session load / validation ── */

Session get_session(const char *user_id) {
    Session s;
    memset(&s, 0, sizeof(s));
    strncpy(s.user_id, user_id, sizeof(s.user_id) - 1);
    /* authenticated flag not set here — caller must verify */
    return s;
}

Session load_session(uint32_t token) {
    Session s = current_session;
    s.token = token;
    return s;  /* returns possibly stale session */
}

bool check_authenticated(const Session *s) {
    return s->authenticated && !s->expired;
}

bool verify_session(const Session *s) {
    return s->token != 0 && !s->expired;
}

void invalidate(Session *s) {
    s->authenticated = false;
    s->expired = true;
    s->token = 0;
}

/* ── privileged actions (sinks) ── */

int admin_action(const char *cmd) {
    (void)cmd;
    return 0;
}

int delete_user(const char *user_id) {
    (void)user_id;
    return 0;
}

int grant_permission(const char *user_id, const char *perm) {
    (void)user_id; (void)perm;
    return 0;
}

int write_config(const char *key, const char *val) {
    (void)key; (void)val;
    return 0;
}

/* ── bad paths ── */

/*
 * BAD: admin_action called on session from load_session without
 * checking authenticated flag. PRIVILEGED_ACTION_WITHOUT_REQUIRED_STATE.
 */
int handle_admin_request_bad(uint32_t token, const char *cmd) {
    Session s = load_session(token);
    /* no check_authenticated / verify_session call */
    return admin_action(cmd);
}

/*
 * BAD: grant_permission called after restoring saved session.
 * Session could be stale (replay). STATE_PERSISTENCE_REPLAY_RISK.
 */
void restore_state(Session *s, uint32_t saved_token) {
    s->token = saved_token;
    s->authenticated = true;  /* blindly set — no re-verification */
}

int grant_on_restored_session(uint32_t saved_token, const char *perm) {
    Session s;
    restore_state(&s, saved_token);
    /* authenticated is set but token not re-verified against server */
    return grant_permission(s.user_id, perm);
}

/*
 * BAD: write_config with stale session — expired flag not checked.
 */
int write_config_stale(const char *key, const char *val) {
    Session s = current_session;
    /* s.expired not checked — stale session reuse */
    if (s.authenticated) {
        return write_config(key, val);
    }
    return -1;
}

/* ── good paths ── */

/*
 * GOOD: check_authenticated before admin_action.
 */
int handle_admin_request_good(uint32_t token, const char *cmd) {
    Session s = load_session(token);
    if (!check_authenticated(&s)) {
        return -1;
    }
    return admin_action(cmd);
}

/*
 * GOOD: verify_session before grant_permission.
 */
int grant_with_verification(uint32_t token, const char *perm) {
    Session s = load_session(token);
    if (!verify_session(&s)) {
        return -1;
    }
    return grant_permission(s.user_id, perm);
}
