/**
 * fixture: update_integrity/updater.c
 *
 * Target scenario: secure_update_install_integrity
 *
 * Structural candidates expected:
 *   - install_without_verify: install_firmware called without prior verify_signature
 *   - stale_header_reuse: trusted_header used after failed update (stale state)
 *   - version_check_skipped: apply_update proceeds without version fence
 */

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

typedef struct {
    uint8_t  magic[4];
    uint32_t version;
    uint32_t size;
    uint8_t  signature[64];
    bool     verified;
} FirmwareHeader;

static FirmwareHeader trusted_header;

/* ── receive & verify ── */

int receive_package(uint8_t *buf, int maxlen) {
    /* reads from network — source */
    return 0;
}

bool verify_signature(const FirmwareHeader *hdr) {
    /* checks cryptographic signature */
    return hdr->signature[0] != 0;
}

bool check_integrity(const uint8_t *data, uint32_t size) {
    return size > 0;
}

/* ── install paths ── */

/*
 * BAD PATH A: install_firmware called directly after receive_package
 * without verify_signature — UPDATE_PATH_WITHOUT_AUTHENTICITY_CHECK candidate.
 */
int install_without_verify(const uint8_t *pkg, uint32_t size) {
    FirmwareHeader hdr;
    memcpy(&hdr, pkg, sizeof(FirmwareHeader));
    /* no verify_signature call here */
    return install_firmware(pkg, size);  /* sink reached without guard */
}

int install_firmware(const uint8_t *image, uint32_t size) {
    /* writes to flash — sink */
    (void)image; (void)size;
    return 0;
}

/*
 * BAD PATH B: update fails, but trusted_header is left populated.
 * Subsequent call to apply_update reuses the stale state.
 * stale trusted metadata reuse candidate.
 */
int do_update_with_stale_reuse(const uint8_t *pkg, uint32_t size) {
    FirmwareHeader new_hdr;
    memcpy(&new_hdr, pkg, sizeof(FirmwareHeader));

    if (!verify_signature(&new_hdr)) {
        /* error: trusted_header NOT cleared here — stale state remains */
        return -1;
    }
    trusted_header = new_hdr;
    trusted_header.verified = true;
    return 0;
}

/* later call reuses trusted_header without re-validation */
int apply_update_stale(void) {
    /* trusted_header.verified may be stale from a previous failed cycle */
    if (trusted_header.verified) {
        return apply_update(&trusted_header);
    }
    return -1;
}

int apply_update(const FirmwareHeader *hdr) {
    /* sink: activates firmware */
    (void)hdr;
    return 0;
}

/*
 * GOOD PATH: verify before install — should not generate ACTIVE candidate.
 */
int install_with_verify(const uint8_t *pkg, uint32_t size) {
    FirmwareHeader hdr;
    memcpy(&hdr, pkg, sizeof(FirmwareHeader));

    if (!verify_signature(&hdr)) {
        return -1;
    }
    if (!check_integrity(pkg, size)) {
        return -1;
    }
    return install_firmware(pkg, size);
}

/* ── version / rollback ── */

uint32_t get_current_version(void) { return 1; }

/*
 * BAD: version comparison missing — rollback not prevented.
 * VERSION_POLICY_WEAK_OR_INCONSISTENT candidate.
 */
int flash_image(const FirmwareHeader *hdr, const uint8_t *data) {
    /* no version check before flash — sink */
    (void)hdr; (void)data;
    return 0;
}

int update_no_version_check(const FirmwareHeader *hdr, const uint8_t *data) {
    if (!verify_signature(hdr)) return -1;
    /* version not compared against current — rollback possible */
    return flash_image(hdr, data);
}
