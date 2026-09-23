#ifndef JW_LAUNCHER_RA_ACCOUNT_H
#define JW_LAUNCHER_RA_ACCOUNT_H

#include <stdbool.h>

#include "internal/db/db.h"
#include "internal/launcher/standalone_policy.h"

/* Producer side of standalone-ra-account-v1: the versioned RetroAchievements
   account snapshot the daemon exports to one authorized standalone emulator
   after fork(). The five variables are child-only per-launch state; they are
   never written to env.sh, logs, argv, manifests or the daemon's own
   environment. */

#define JW_RA_ACCOUNT_CONTRACT_ID   "standalone-ra-account-v1"
#define JW_RA_ACCOUNT_ENV_VERSION   "UMRK_RA_ACCOUNT_VERSION"
#define JW_RA_ACCOUNT_ENV_STATE     "UMRK_RA_ACCOUNT_STATE"
#define JW_RA_ACCOUNT_ENV_USERNAME  "UMRK_RA_ACCOUNT_USERNAME"
#define JW_RA_ACCOUNT_ENV_PASSWORD  "UMRK_RA_ACCOUNT_PASSWORD"
#define JW_RA_ACCOUNT_ENV_REVISION  "UMRK_RA_ACCOUNT_REVISION"

/* Contract state strings, by jw_ra_account_state value. NULL for out-of-range
   values (a caller bug; treat as no handoff). */
const char *jw_ra_account_state_name(jw_ra_account_state state);

/* Decide whether a fully resolved standalone launch target may receive the
   account snapshot. This is deliberately NOT display policy: it never grants
   direct DRM, and direct-DRM grants never grant credentials.

   Authorized today, and only today:

   - Bundled Flycast: a release-owned core whose resolved launcher is EXACTLY
     <platform_dir>/emulators/flycast/launch.sh, and whose installed payload
     carries the narrow capability record
     <platform_dir>/emulators/flycast/ra-account-v1 with the contract id as
     its content. A matching core id, filename or substring alone is not
     enough, and a provider-bound core never takes this branch.

   - DSperate: a provider-bound core with provider "mlp1/DSperate.pak", core
     id "dsperate", resolved launcher exactly <pak>/scripts/run.sh, and an
     installed <pak>/pak.json with id "org.umrk.dsperate" and
     pak_version >= 2.1.1. The published 2.0.0 build does not consume the
     contract, so it receives no credentials.

   Everything else, and every check that cannot be positively established
   (missing files, unreadable manifests, malformed versions), is refused. */
bool jw_ra_account_target_authorized(const char *launcher_path,
                                     const char *core_id,
                                     const jw_standalone_policy *policy,
                                     const char *provider,
                                     const char *platform_dir);

/* RAOfflineProxy service intent for bundled Flycast (proxy plan P2). A
   private child-only variable, separate from the account snapshot: it names
   whether the supervised proxy service may be used, never a URL, port or
   credential, and never that the game is eligible or that health passed.
   Flycast decides the session route itself after loading its real per-game
   settings (P3). Missing or unknown values never opt into proxy routing. */
#define JW_FLYCAST_RA_ROUTE_ENV           "UMRK_FLYCAST_RA_ROUTE"
#define JW_FLYCAST_RA_ROUTE_SERVICE_LIVE  "service-live"
#define JW_FLYCAST_RA_ROUTE_NATIVE        "native"
#define JW_FLYCAST_RA_ROUTE_CAPABILITY_ID "umrk-flycast-ra-route-v1"

/* Decide whether a resolved standalone target may receive
   UMRK_FLYCAST_RA_ROUTE. Only the bundled Flycast target qualifies: it must
   already be authorized for the account snapshot, and its installed payload
   must also carry <platform_dir>/emulators/flycast/ra-route-v1 whose content
   is JW_FLYCAST_RA_ROUTE_CAPABILITY_ID. A build with account import but no
   routing support keeps its native path. DSperate and every other target are
   refused whatever their account authorization says. */
bool jw_flycast_ra_route_target_authorized(const char *launcher_path,
                                           const char *core_id,
                                           const jw_standalone_policy *policy,
                                           const char *provider,
                                           const char *platform_dir);

/* The handoff value for an authorized target: "service-live" only when the
   supervised service is live, "native" otherwise. */
const char *jw_flycast_ra_route_value(bool service_live);

#endif
