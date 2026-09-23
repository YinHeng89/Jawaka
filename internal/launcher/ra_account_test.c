/* standalone-ra-account-v1 launch authorization tests: the exact target and
   capability checks that decide whether a standalone child receives the
   account snapshot. Covers the bundled-Flycast launcher/marker pair, the
   DSperate provider/core/path/manifest matrix, the separate Flycast proxy
   route record, and the spoof cases that must every time fall to refusal. */

#include "internal/launcher/ra_account.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

static void expect(int ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "ra-account-launch-test: %s\n", what);
        failures++;
    }
}

static char root[PATH_MAX];

static void write_file(const char *rel, const char *content) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", root, rel);
    char *slash = strrchr(path, '/');
    *slash = '\0';
    char cmd[PATH_MAX + 16];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", path);
    if (system(cmd) != 0) exit(1);
    *slash = '/';
    FILE *f = fopen(path, "wb");
    if (!f) exit(1);
    fputs(content, f);
    fclose(f);
}

/* mlp1/DSperate.pak lives under an apps root; run.sh must be executable. */
static void make_dsperate_pak(const char *pak_json) {
    write_file("apps/mlp1/DSperate.pak/pak.json", pak_json);
    char run_sh[PATH_MAX];
    snprintf(run_sh, sizeof(run_sh), "%s/%s", root,
             "apps/mlp1/DSperate.pak/scripts/run.sh");
    write_file("apps/mlp1/DSperate.pak/scripts/run.sh", "#!/bin/sh\n");
    chmod(run_sh, 0755);
}

static const jw_standalone_policy FLYCAST_RELEASE = {
    .provider_bound = false, .release = JW_STANDALONE_RELEASE_FLYCAST,
};
static const jw_standalone_policy PROVIDER_BOUND = {
    .provider_bound = true, .release = JW_STANDALONE_RELEASE_NONE,
};
static const jw_standalone_policy DRASTIC_RELEASE = {
    .provider_bound = false, .release = JW_STANDALONE_RELEASE_DRASTIC,
};

/* Helpers naming the resolved pieces the way the daemon resolves them. */
static void platform_dir(char *out, size_t size) {
    snprintf(out, size, "%s/platform", root);
}
static void flycast_launcher(char *out, size_t size) {
    snprintf(out, size, "%s/platform/emulators/flycast/launch.sh", root);
}
static void dsperate_launcher(char *out, size_t size) {
    snprintf(out, size, "%s/apps/mlp1/DSperate.pak/scripts/run.sh", root);
}

static void test_flycast(void) {
    char platform[PATH_MAX], launcher[PATH_MAX];
    platform_dir(platform, sizeof(platform));
    flycast_launcher(launcher, sizeof(launcher));

    write_file("platform/emulators/flycast/launch.sh", "#!/bin/sh\n");
    write_file("platform/emulators/flycast/ra-account-v1",
               "standalone-ra-account-v1\n");

    expect(jw_ra_account_target_authorized(launcher, "flycast_standalone",
                                           &FLYCAST_RELEASE, NULL, platform),
           "bundled flycast: exact launcher + capability record authorized");

    /* The capability record is required: a filename match alone grants
       nothing. */
    expect(!jw_ra_account_target_authorized(launcher, "flycast_standalone",
                                            &FLYCAST_RELEASE, NULL,
                                            "/nonexistent-platform"),
           "bundled flycast: wrong platform dir denied");

    /* Spoofed provider naming itself after the release: provider-bound cores
       never take the release branch, whatever the files say. */
    expect(!jw_ra_account_target_authorized(launcher, "flycast",
                                            &PROVIDER_BOUND,
                                            "mlp1/not-a-release.pak", platform),
           "provider-bound flycast-named core denied");

    /* A same-named launcher outside the release payload. */
    char other_launcher[PATH_MAX];
    snprintf(other_launcher, sizeof(other_launcher),
             "%s/apps/mlp1/Flycast.pak/launch.sh", root);
    write_file("apps/mlp1/Flycast.pak/launch.sh", "#!/bin/sh\n");
    write_file("apps/mlp1/Flycast.pak/ra-account-v1",
               "standalone-ra-account-v1\n");
    expect(!jw_ra_account_target_authorized(other_launcher, "flycast",
                                            &FLYCAST_RELEASE, NULL, platform),
           "flycast identity outside the release-owned launcher denied");

    /* Wrong marker content. */
    write_file("platform/emulators/flycast/ra-account-v1",
               "standalone-ra-account-v0\n");
    expect(!jw_ra_account_target_authorized(launcher, "flycast_standalone",
                                            &FLYCAST_RELEASE, NULL, platform),
           "stale capability record denied");
    write_file("platform/emulators/flycast/ra-account-v1",
               "standalone-ra-account-v1\n");

    /* Other release standalones never qualify for the Flycast branch. */
    expect(!jw_ra_account_target_authorized(launcher, "drastic",
                                            &DRASTIC_RELEASE, NULL, platform),
           "drastic identity on the flycast path denied");
}

static void test_dsperate(void) {
    char platform[PATH_MAX], launcher[PATH_MAX];
    platform_dir(platform, sizeof(platform));
    dsperate_launcher(launcher, sizeof(launcher));

    make_dsperate_pak(
        "{ \"id\": \"org.umrk.dsperate\", \"name\": \"DSperate\","
        "  \"platform\": \"mlp1\", \"pak_version\": \"2.1.1\","
        "  \"min_leaf_version\": \"0.12.0\" }\n");

    expect(jw_ra_account_target_authorized(launcher, "dsperate",
                                           &PROVIDER_BOUND,
                                           "mlp1/DSperate.pak", platform),
           "validated dsperate pak authorized");

    /* The published 2.0.0 build cannot consume the handoff. */
    make_dsperate_pak(
        "{ \"id\": \"org.umrk.dsperate\", \"platform\": \"mlp1\","
        "  \"pak_version\": \"2.0.0\" }\n");
    expect(!jw_ra_account_target_authorized(launcher, "dsperate",
                                            &PROVIDER_BOUND,
                                            "mlp1/DSperate.pak", platform),
           "dsperate 2.0.0 denied");
    make_dsperate_pak(
        "{ \"id\": \"org.umrk.dsperate\", \"platform\": \"mlp1\","
        "  \"pak_version\": \"2.1.1\" }\n");

    /* A malformed version is not a capability. */
    make_dsperate_pak(
        "{ \"id\": \"org.umrk.dsperate\", \"platform\": \"mlp1\","
        "  \"pak_version\": \"2.1.1+leaf.1\" }\n");
    expect(!jw_ra_account_target_authorized(launcher, "dsperate",
                                            &PROVIDER_BOUND,
                                            "mlp1/DSperate.pak", platform),
           "unparseable dsperate version denied");
    make_dsperate_pak(
        "{ \"id\": \"org.umrk.dsperate\", \"platform\": \"mlp1\","
        "  \"pak_version\": \"2.1.1\" }\n");

    /* A pak claiming DSperate's identity from the wrong provider path, or the
       right pak with the wrong store id, is denied. */
    expect(!jw_ra_account_target_authorized(launcher, "dsperate",
                                            &PROVIDER_BOUND,
                                            "mlp1/Impostor.pak", platform),
           "wrong provider denied");
    make_dsperate_pak(
        "{ \"id\": \"org.umrk.impostor\", \"platform\": \"mlp1\","
        "  \"pak_version\": \"2.1.1\" }\n");
    expect(!jw_ra_account_target_authorized(launcher, "dsperate",
                                            &PROVIDER_BOUND,
                                            "mlp1/DSperate.pak", platform),
           "wrong manifest id denied");
    make_dsperate_pak(
        "{ \"id\": \"org.umrk.dsperate\", \"platform\": \"mlp1\","
        "  \"pak_version\": \"2.1.1\" }\n");

    /* Right provider, wrong core id or wrong pak-relative launcher. */
    expect(!jw_ra_account_target_authorized(launcher, "scummvm",
                                            &PROVIDER_BOUND,
                                            "mlp1/DSperate.pak", platform),
           "wrong core id denied");
    char wrong_launcher[PATH_MAX];
    snprintf(wrong_launcher, sizeof(wrong_launcher),
             "%s/apps/mlp1/DSperate.pak/launch.sh", root);
    expect(!jw_ra_account_target_authorized(wrong_launcher, "dsperate",
                                            &PROVIDER_BOUND,
                                            "mlp1/DSperate.pak", platform),
           "non-run.sh launcher denied");

    /* A release-recognized path-core (never provider-bound in the real
       catalog) cannot reach the provider branch. */
    expect(!jw_ra_account_target_authorized(launcher, "dsperate",
                                            &FLYCAST_RELEASE,
                                            "mlp1/DSperate.pak", platform),
           "release policy cannot take the provider branch");

    /* Missing manifest. */
    char manifest[PATH_MAX];
    snprintf(manifest, sizeof(manifest), "%s/apps/mlp1/DSperate.pak/pak.json",
             root);
    char saved[PATH_MAX];
    snprintf(saved, sizeof(saved), "%s.pakjson-saved", manifest);
    rename(manifest, saved);
    expect(!jw_ra_account_target_authorized(launcher, "dsperate",
                                            &PROVIDER_BOUND,
                                            "mlp1/DSperate.pak", platform),
           "missing manifest denied");
    rename(saved, manifest);
}

/* UMRK_FLYCAST_RA_ROUTE authorization (proxy plan P2): the bundled Flycast
   target only, and only when its payload carries both the account record and
   the separate route record. */
static void test_flycast_route(void) {
    char platform[PATH_MAX], launcher[PATH_MAX], other[PATH_MAX];
    platform_dir(platform, sizeof(platform));
    flycast_launcher(launcher, sizeof(launcher));
    snprintf(other, sizeof(other), "%s/apps/mlp1/Flycast.pak/launch.sh", root);
    char route_record[PATH_MAX], account_record[PATH_MAX], saved[PATH_MAX];
    snprintf(route_record, sizeof(route_record),
             "%s/platform/emulators/flycast/ra-route-v1", root);
    snprintf(account_record, sizeof(account_record),
             "%s/platform/emulators/flycast/ra-account-v1", root);

    write_file("platform/emulators/flycast/launch.sh", "#!/bin/sh\n");
    write_file("platform/emulators/flycast/ra-account-v1",
               "standalone-ra-account-v1\n");

    /* An account-capable build without the route record keeps its native
       path: account import alone is not routing support. */
    expect(!jw_flycast_ra_route_target_authorized(launcher,
                                                  "flycast_standalone",
                                                  &FLYCAST_RELEASE, NULL,
                                                  platform),
           "route: account-only flycast build denied");

    write_file("platform/emulators/flycast/ra-route-v1",
               "umrk-flycast-ra-route-v1\n");
    expect(jw_flycast_ra_route_target_authorized(launcher,
                                                 "flycast_standalone",
                                                 &FLYCAST_RELEASE, NULL,
                                                 platform),
           "route: bundled flycast with both records authorized");
    write_file("platform/emulators/flycast/ra-route-v1",
               "umrk-flycast-ra-route-v1");
    expect(jw_flycast_ra_route_target_authorized(launcher,
                                                 "flycast_standalone",
                                                 &FLYCAST_RELEASE, NULL,
                                                 platform),
           "route: record without trailing newline authorized");

    /* The route record never stands in for the account record. */
    snprintf(saved, sizeof(saved), "%s.saved", account_record);
    rename(account_record, saved);
    expect(!jw_flycast_ra_route_target_authorized(launcher,
                                                  "flycast_standalone",
                                                  &FLYCAST_RELEASE, NULL,
                                                  platform),
           "route: missing account record denied");
    rename(saved, account_record);

    /* Stale, padded or foreign record content. */
    static const char *const bad[] = {
        "umrk-flycast-ra-route-v0\n", "umrk-flycast-ra-route-v1\n\n",
        " umrk-flycast-ra-route-v1\n", "standalone-ra-account-v1\n", "",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        write_file("platform/emulators/flycast/ra-route-v1", bad[i]);
        expect(!jw_flycast_ra_route_target_authorized(launcher,
                                                      "flycast_standalone",
                                                      &FLYCAST_RELEASE, NULL,
                                                      platform),
               "route: malformed route record denied");
    }
    write_file("platform/emulators/flycast/ra-route-v1",
               "umrk-flycast-ra-route-v1\n");

    /* A sideloaded launcher named like Flycast, carrying both records, and a
       provider-bound core claiming the release identity. */
    write_file("apps/mlp1/Flycast.pak/launch.sh", "#!/bin/sh\n");
    write_file("apps/mlp1/Flycast.pak/ra-account-v1",
               "standalone-ra-account-v1\n");
    write_file("apps/mlp1/Flycast.pak/ra-route-v1",
               "umrk-flycast-ra-route-v1\n");
    expect(!jw_flycast_ra_route_target_authorized(other, "flycast",
                                                  &FLYCAST_RELEASE, NULL,
                                                  platform),
           "route: flycast launcher outside the release payload denied");
    expect(!jw_flycast_ra_route_target_authorized(launcher, "flycast",
                                                  &PROVIDER_BOUND,
                                                  "mlp1/Flycast.pak",
                                                  platform),
           "route: provider-bound flycast-named core denied");
    expect(!jw_flycast_ra_route_target_authorized(launcher, "drastic",
                                                  &DRASTIC_RELEASE, NULL,
                                                  platform),
           "route: other release standalone denied");

    /* DSperate is account-authorized and must still never get the route. */
    char dsperate[PATH_MAX];
    dsperate_launcher(dsperate, sizeof(dsperate));
    make_dsperate_pak(
        "{ \"id\": \"org.umrk.dsperate\", \"platform\": \"mlp1\","
        "  \"pak_version\": \"2.1.1\" }\n");
    write_file("apps/mlp1/DSperate.pak/ra-route-v1",
               "umrk-flycast-ra-route-v1\n");
    expect(jw_ra_account_target_authorized(dsperate, "dsperate",
                                           &PROVIDER_BOUND,
                                           "mlp1/DSperate.pak", platform),
           "route: dsperate fixture is account-authorized");
    expect(!jw_flycast_ra_route_target_authorized(dsperate, "dsperate",
                                                  &PROVIDER_BOUND,
                                                  "mlp1/DSperate.pak",
                                                  platform),
           "route: account-authorized dsperate denied the flycast route");

    expect(!jw_flycast_ra_route_target_authorized(NULL, "flycast_standalone",
                                                  &FLYCAST_RELEASE, NULL,
                                                  platform) &&
               !jw_flycast_ra_route_target_authorized(launcher,
                                                      "flycast_standalone",
                                                      NULL, NULL, platform),
           "route: missing inputs denied");

    expect(strcmp(jw_flycast_ra_route_value(true), "service-live") == 0,
           "route value: live service");
    expect(strcmp(jw_flycast_ra_route_value(false), "native") == 0,
           "route value: no live service");
}

static void test_env_contract_names(void) {
    expect(strcmp(jw_ra_account_state_name(JW_RA_ACCOUNT_CONFIGURED),
                  "configured") == 0, "state configured");
    expect(strcmp(jw_ra_account_state_name(JW_RA_ACCOUNT_NEVER_CONFIGURED),
                  "never-configured") == 0, "state never-configured");
    expect(strcmp(jw_ra_account_state_name(JW_RA_ACCOUNT_SIGNED_OUT),
                  "signed-out") == 0, "state signed-out");
    expect(strcmp(jw_ra_account_state_name(JW_RA_ACCOUNT_INVALID),
                  "invalid") == 0, "state invalid");
    expect(strcmp(jw_ra_account_state_name(JW_RA_ACCOUNT_UNREADABLE),
                  "unreadable") == 0, "state unreadable");
    expect(jw_ra_account_state_name((jw_ra_account_state)999) == NULL,
           "out-of-range state has no name");
}

int main(void) {
    snprintf(root, sizeof(root), "/tmp/jawaka-ra-launch.XXXXXX");
    if (!mkdtemp(root)) {
        perror("mkdtemp");
        return 1;
    }

    test_flycast();
    test_dsperate();
    test_flycast_route();
    test_env_contract_names();

    if (failures) {
        fprintf(stderr, "ra-account-launch-test: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("ra-account-launch-test: ok\n");
    return 0;
}
