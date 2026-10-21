#!/usr/bin/env bash
# End-to-end check of the example server over real HTTP.
#   BASE            server address              (default http://localhost:3000)
#   ORIGIN          an allowed origin           (default http://localhost:3000)
#   ADMIN_EMAIL / ADMIN_PASSWORD, VIEWER_EMAIL / VIEWER_PASSWORD   seeded accounts
#   SERVER_LOG      server stdout, if the server ran with LOG_RESET_LINKS=1 (enables the reset-flow checks)
set -u
BASE=${BASE:-http://localhost:3000}
ORIGIN=${ORIGIN:-http://localhost:3000}
ADMIN_EMAIL=${ADMIN_EMAIL:-admin@example.test}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-correct-horse-9}
VIEWER_EMAIL=${VIEWER_EMAIL:-viewer@example.test}
VIEWER_PASSWORD=${VIEWER_PASSWORD:-viewer-password-9}
JAR=$(mktemp); VJAR=$(mktemp); trap 'rm -f "$JAR" "$VJAR"' EXIT
pass=0; fail=0

status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
check() { # name expected actual
  if [ "$2" = "$3" ]; then pass=$((pass+1)); printf '  ok    %s (%s)\n' "$1" "$3"; else fail=$((fail+1)); printf '  FAIL  %s (expected %s, got %s)\n' "$1" "$2" "$3"; fi
}
creds() { printf '{"email":"%s","password":"%s"}' "$1" "$2"; }
tokenbody() { printf '{"token":"%s","password":"%s"}' "$1" "$2"; }
emailbody() { printf '{"email":"%s"}' "$1"; }
post() { # jar path body [extra curl args]
  local jar=$1 path=$2 body=$3; shift 3
  curl -s -o /dev/null -w '%{http_code}' -b "$jar" -c "$jar" -H "Content-Type: application/json" -H "Origin: $ORIGIN" -X POST --data "$body" "$@" "$BASE$path"
}

echo "authcore-ts example server: $BASE"
check "healthz" 200 "$(status "$BASE/healthz")"
check "wrong password is rejected" 401 "$(post "$JAR" /auth/sign-in "$(creds "$ADMIN_EMAIL" nope-nope-1)")"
check "unknown user gets the same answer" 401 "$(post "$JAR" /auth/sign-in "$(creds ghost@example.test nope-nope-1)")"
check "cross-origin sign-in is blocked" 403 "$(status -X POST -H 'Content-Type: application/json' -H 'Origin: https://evil.example' --data "$(creds "$ADMIN_EMAIL" "$ADMIN_PASSWORD")" "$BASE/auth/sign-in")"
check "sign-in with no origin is blocked" 403 "$(status -X POST -H 'Content-Type: application/json' --data "$(creds "$ADMIN_EMAIL" "$ADMIN_PASSWORD")" "$BASE/auth/sign-in")"
check "/me without a session" 401 "$(status "$BASE/me")"
check "admin signs in" 200 "$(post "$JAR" /auth/sign-in "$(creds "$ADMIN_EMAIL" "$ADMIN_PASSWORD")")"
check "session cookie is HttpOnly" 1 "$(grep -c '#HttpOnly_' "$JAR")"
check "/me with the session" 200 "$(status -b "$JAR" "$BASE/me")"
check "admin may manage users" 200 "$(status -b "$JAR" "$BASE/admin/users")"
check "viewer signs in" 200 "$(post "$VJAR" /auth/sign-in "$(creds "$VIEWER_EMAIL" "$VIEWER_PASSWORD")")"
check "viewer may read reports" 200 "$(status -b "$VJAR" "$BASE/admin/reports")"
check "viewer may NOT manage users" 403 "$(status -b "$VJAR" "$BASE/admin/users")"

if [ -n "${SERVER_LOG:-}" ]; then
  echo "password reset (revokes sessions):"
  check "forgot answers 202 for a real email" 202 "$(post /dev/null /auth/forgot "$(emailbody "$ADMIN_EMAIL")")"
  check "forgot answers 202 for an unknown email" 202 "$(post /dev/null /auth/forgot "$(emailbody ghost@example.test)")"
  sleep 1
  TOKEN=$(grep "reset link for $ADMIN_EMAIL" "$SERVER_LOG" | tail -1 | sed 's#.*/reset/##')
  check "reset token was issued" 1 "$([ -n "$TOKEN" ] && echo 1 || echo 0)"
  check "weak password is refused (token not burned)" 400 "$(post /dev/null /auth/reset "$(tokenbody "$TOKEN" short)")"
  check "reset with the token works" 200 "$(post /dev/null /auth/reset "$(tokenbody "$TOKEN" a-brand-new-pass-2)")"
  check "the token cannot be reused" 400 "$(post /dev/null /auth/reset "$(tokenbody "$TOKEN" another-new-pass-3)")"
  check "the OLD session is now revoked" 401 "$(status -b "$JAR" "$BASE/me")"
  check "old password no longer works" 401 "$(post "$JAR" /auth/sign-in "$(creds "$ADMIN_EMAIL" "$ADMIN_PASSWORD")")"
  check "new password works" 200 "$(post "$JAR" /auth/sign-in "$(creds "$ADMIN_EMAIL" a-brand-new-pass-2)")"
fi

echo "rate limiting:"
last=000
for _ in $(seq 1 10); do last=$(post /dev/null /auth/sign-in "$(creds brute@example.test nope-nope-1)"); done
check "the 10th rapid attempt is throttled" 429 "$last"

echo; echo "passed: $pass   failed: $fail"
[ "$fail" -eq 0 ]
