#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CREDS_FILE="${SCRIPT_DIR}/.lab-credentials"
GITIGNORE_FILE="${SCRIPT_DIR}/.gitignore"

JELLYFIN_URL="http://172.31.250.10:8096"
DIRECTUS_URL="http://172.31.250.11:8055"

LAB_ADMIN_PASSWORD="${LAB_ADMIN_PASSWORD:-LabAdminPass123!}"
LAB_USER2_PASSWORD="${LAB_USER2_PASSWORD:-LabUser2Pass123!}"

EMBY_AUTH_BASE='MediaBrowser Client="lab-setup", Device="setup-script", DeviceId="lab-setup-1", Version="1.0.0"'

RESP_BODY=""
RESP_CODE=""

die() {
  echo "ERROR: $*" >&2
  exit 1
}

# Usage: http_call METHOD URL [DATA] [HEADER...]
http_call() {
  local method="$1"
  local url="$2"
  local data="${3:-}"
  shift 2
  if [ "$#" -gt 0 ]; then
    shift 1
  fi

  local -a args=(-sS -X "$method" -w $'\n%{http_code}')
  local hdr
  for hdr in "$@"; do
    args+=(-H "$hdr")
  done
  if [ -n "$data" ]; then
    args+=(-H "Content-Type: application/json" -d "$data")
  fi

  local raw
  if ! raw="$(curl "${args[@]}" "$url")"; then
    die "curl failed for ${method} ${url}"
  fi

  RESP_CODE="${raw##*$'\n'}"
  if [ "$raw" = "$RESP_CODE" ]; then
    RESP_BODY=""
  else
    RESP_BODY="${raw%$'\n'*}"
  fi
}

require_status() {
  local expected="$1"
  local context="$2"
  local ok=1
  local code
  for code in $expected; do
    if [ "$RESP_CODE" = "$code" ]; then
      ok=0
      break
    fi
  done
  if [ "$ok" -ne 0 ]; then
    die "${context}: expected HTTP [${expected}], got HTTP ${RESP_CODE}. Body: ${RESP_BODY}"
  fi
}

wait_for_url() {
  local name="$1"
  local url="$2"
  local i
  echo "Waiting for ${name} at ${url}..."
  for i in $(seq 1 30); do
    if curl -sS -o /dev/null --max-time 2 "$url"; then
      echo "${name} is reachable."
      return 0
    fi
    sleep 2
  done
  die "${name} did not become reachable at ${url} within 60s"
}

json_eval() {
  python3 -c "$1" "${@:2}"
}

ensure_gitignore() {
  if [ ! -f "$GITIGNORE_FILE" ] || ! grep -qxF '.lab-credentials' "$GITIGNORE_FILE"; then
    echo '.lab-credentials' >> "$GITIGNORE_FILE"
  fi
}

setup_jellyfin() {
  wait_for_url "Jellyfin" "${JELLYFIN_URL}/System/Info/Public"

  http_call GET "${JELLYFIN_URL}/System/Info/Public"
  require_status "200" "Jellyfin GET /System/Info/Public"

  local wizard_done
  wizard_done="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; d=json.load(sys.stdin); print("true" if d.get("StartupWizardCompleted") else "false")')"

  if [ "$wizard_done" != "true" ]; then
    echo "Completing Jellyfin startup wizard..."
    # Some Jellyfin versions initialize the default user on GET /Startup/User.
    http_call GET "${JELLYFIN_URL}/Startup/User" || true

    local cfg_payload='{"UICulture":"en-US","MetadataCountryCode":"US","PreferredMetadataLanguage":"en"}'
    http_call POST "${JELLYFIN_URL}/Startup/Configuration" "$cfg_payload"
    require_status "200 204" "Jellyfin POST /Startup/Configuration"

    local user_payload
    user_payload="$(json_eval 'import json,sys; print(json.dumps({"Name":"admin","Password":sys.argv[1]}))' "$LAB_ADMIN_PASSWORD")"
    http_call POST "${JELLYFIN_URL}/Startup/User" "$user_payload"
    require_status "200 204" "Jellyfin POST /Startup/User"

    http_call POST "${JELLYFIN_URL}/Startup/Complete" ""
    require_status "200 204" "Jellyfin POST /Startup/Complete"
  else
    echo "Jellyfin startup wizard already completed."
  fi

  echo "Logging into Jellyfin as admin..."
  local auth_payload
  auth_payload="$(json_eval 'import json,sys; print(json.dumps({"Username":"admin","Pw":sys.argv[1]}))' "$LAB_ADMIN_PASSWORD")"
  http_call POST "${JELLYFIN_URL}/Users/AuthenticateByName" "$auth_payload" "Authorization: ${EMBY_AUTH_BASE}"
  require_status "200" "Jellyfin POST /Users/AuthenticateByName"

  local jf_token
  jf_token="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(json.load(sys.stdin)["AccessToken"])')"
  local emby_auth="${EMBY_AUTH_BASE}, Token=\"${jf_token}\""

  http_call GET "${JELLYFIN_URL}/Users" "" "Authorization: ${emby_auth}"
  require_status "200" "Jellyfin GET /Users"

  local user2_id
  user2_id="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys
users=json.load(sys.stdin)
for u in users:
    if u.get("Name")=="user2":
        print(u.get("Id",""))
        break
')"

  if [ -z "$user2_id" ]; then
    echo "Creating Jellyfin user2..."
    local new_user_payload
    new_user_payload="$(json_eval 'import json,sys; print(json.dumps({"Name":"user2","Password":sys.argv[1]}))' "$LAB_USER2_PASSWORD")"
    http_call POST "${JELLYFIN_URL}/Users/New" "$new_user_payload" "Authorization: ${emby_auth}"
    require_status "200 201" "Jellyfin POST /Users/New"
    user2_id="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(json.load(sys.stdin)["Id"])')"
  else
    echo "Jellyfin user2 already exists (${user2_id})."
  fi

  echo "Disabling Jellyfin plugin repositories..."
  http_call POST "${JELLYFIN_URL}/Repositories" "[]" "Authorization: ${emby_auth}"
  require_status "200 204" "Jellyfin POST /Repositories"

  echo "Disabling Jellyfin metrics in system configuration..."
  http_call GET "${JELLYFIN_URL}/System/Configuration" "" "Authorization: ${emby_auth}"
  require_status "200" "Jellyfin GET /System/Configuration"
  local updated_cfg
  updated_cfg="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys
cfg=json.load(sys.stdin)
cfg["EnableMetrics"]=False
print(json.dumps(cfg))
')"
  http_call POST "${JELLYFIN_URL}/System/Configuration" "$updated_cfg" "Authorization: ${emby_auth}"
  require_status "200 204" "Jellyfin POST /System/Configuration"
}

setup_directus() {
  wait_for_url "Directus" "${DIRECTUS_URL}/server/ping"

  echo "Logging into Directus as admin@example.com..."
  local login_payload
  login_payload="$(json_eval 'import json,sys; print(json.dumps({"email":"admin@example.com","password":sys.argv[1]}))' "$LAB_ADMIN_PASSWORD")"
  http_call POST "${DIRECTUS_URL}/auth/login" "$login_payload"
  require_status "200" "Directus POST /auth/login"

  local token
  token="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(json.load(sys.stdin)["data"]["access_token"])')"
  local auth_hdr="Authorization: Bearer ${token}"

  http_call GET "${DIRECTUS_URL}/users/me" "" "$auth_hdr"
  require_status "200" "Directus GET /users/me"
  local admin_id
  admin_id="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(json.load(sys.stdin)["data"]["id"])')"

  # Role: Editor
  http_call GET "${DIRECTUS_URL}/roles?filter%5Bname%5D%5B_eq%5D=Editor" "" "$auth_hdr"
  require_status "200" "Directus GET /roles"
  local role_id
  role_id="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; d=json.load(sys.stdin)["data"]; print(d[0]["id"] if d else "")')"
  if [ -z "$role_id" ]; then
    echo "Creating Directus role Editor..."
    http_call POST "${DIRECTUS_URL}/roles" '{"name":"Editor","icon":"supervised_user_circle","description":"Lab Editor role"}' "$auth_hdr"
    require_status "200 201" "Directus POST /roles"
    role_id="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(json.load(sys.stdin)["data"]["id"])')"
  else
    echo "Directus role Editor already exists (${role_id})."
  fi

  # Policy: Editor (Directus 11+/12 uses policies linked to roles)
  http_call GET "${DIRECTUS_URL}/policies?filter%5Bname%5D%5B_eq%5D=Editor" "" "$auth_hdr"
  require_status "200" "Directus GET /policies"
  local policy_id
  policy_id="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; d=json.load(sys.stdin)["data"]; print(d[0]["id"] if d else "")')"
  if [ -z "$policy_id" ]; then
    echo "Creating Directus policy Editor..."
    local policy_payload
    policy_payload="$(json_eval 'import json,sys; print(json.dumps({"name":"Editor","icon":"badge","app_access":True,"admin_access":False,"roles":[{"role":sys.argv[1]}]}))' "$role_id")"
    http_call POST "${DIRECTUS_URL}/policies" "$policy_payload" "$auth_hdr"
    require_status "200 201" "Directus POST /policies"
    policy_id="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(json.load(sys.stdin)["data"]["id"])')"
  else
    echo "Directus policy Editor already exists (${policy_id})."
  fi

  # Collection: notes
  http_call GET "${DIRECTUS_URL}/collections/notes" "" "$auth_hdr"
  if [ "$RESP_CODE" = "404" ] || [ "$RESP_CODE" = "403" ]; then
    echo "Creating Directus collection notes..."
    local coll_payload='{
      "collection": "notes",
      "meta": { "icon": "note", "note": "Lab notes for BOLA testing" },
      "schema": {},
      "fields": [
        {
          "field": "id",
          "type": "integer",
          "meta": { "hidden": true, "interface": "input", "readonly": true },
          "schema": { "is_primary_key": true, "has_auto_increment": true }
        },
        {
          "field": "title",
          "type": "string",
          "meta": { "interface": "input", "required": true },
          "schema": { "is_nullable": false }
        },
        {
          "field": "body",
          "type": "text",
          "meta": { "interface": "input-multiline" },
          "schema": { "is_nullable": true }
        },
        {
          "field": "owner",
          "type": "string",
          "meta": { "interface": "input" },
          "schema": { "is_nullable": true }
        }
      ]
    }'
    http_call POST "${DIRECTUS_URL}/collections" "$coll_payload" "$auth_hdr"
    require_status "200 201" "Directus POST /collections"
  else
    require_status "200" "Directus GET /collections/notes"
    echo "Directus collection notes already exists."
  fi

  # Permission: Editor read access to notes
  http_call GET "${DIRECTUS_URL}/permissions?filter%5Bpolicy%5D%5B_eq%5D=${policy_id}&filter%5Bcollection%5D%5B_eq%5D=notes" "" "$auth_hdr"
  require_status "200" "Directus GET /permissions"
  local perm_count
  perm_count="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(len(json.load(sys.stdin)["data"]))')"
  if [ "$perm_count" -eq 0 ]; then
    echo "Granting Editor policy read permission on notes..."
    local perm_payload
    perm_payload="$(json_eval 'import json,sys; print(json.dumps({"policy":sys.argv[1],"collection":"notes","action":"read","fields":["*"]}))' "$policy_id")"
    http_call POST "${DIRECTUS_URL}/permissions" "$perm_payload" "$auth_hdr"
    require_status "200 201" "Directus POST /permissions"
  else
    echo "Directus Editor permission on notes already exists."
  fi

  # User: user2@example.com
  http_call GET "${DIRECTUS_URL}/users?filter%5Bemail%5D%5B_eq%5D=user2%40example.com" "" "$auth_hdr"
  require_status "200" "Directus GET /users"
  local user2_id
  user2_id="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; d=json.load(sys.stdin)["data"]; print(d[0]["id"] if d else "")')"
  if [ -z "$user2_id" ]; then
    echo "Creating Directus user2@example.com..."
    local u2_payload
    u2_payload="$(json_eval 'import json,sys; print(json.dumps({"email":"user2@example.com","password":sys.argv[1],"role":sys.argv[2],"status":"active"}))' "$LAB_USER2_PASSWORD" "$role_id")"
    http_call POST "${DIRECTUS_URL}/users" "$u2_payload" "$auth_hdr"
    require_status "200 201" "Directus POST /users"
    user2_id="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(json.load(sys.stdin)["data"]["id"])')"
  else
    echo "Directus user2@example.com already exists (${user2_id})."
  fi

  # Seed items in notes for admin and user2 (idempotent by title)
  http_call GET "${DIRECTUS_URL}/items/notes?limit=-1" "" "$auth_hdr"
  require_status "200" "Directus GET /items/notes"
  local existing_titles
  existing_titles="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print("\n".join(str(x.get("title","")) for x in json.load(sys.stdin)["data"]))')"

  create_note_if_missing() {
    local title="$1"
    local body="$2"
    local owner="$3"
    if printf '%s\n' "$existing_titles" | grep -qxF "$title"; then
      echo "Note '${title}' already exists."
      return 0
    fi
    local item_payload
    item_payload="$(json_eval 'import json,sys; print(json.dumps({"title":sys.argv[1],"body":sys.argv[2],"owner":sys.argv[3]}))' "$title" "$body" "$owner")"
    http_call POST "${DIRECTUS_URL}/items/notes" "$item_payload" "$auth_hdr"
    require_status "200 201" "Directus POST /items/notes (${title})"
    echo "Created note '${title}'."
  }

  create_note_if_missing "admin-note-1" "First lab note owned by admin" "$admin_id"
  create_note_if_missing "admin-note-2" "Second lab note owned by admin" "$admin_id"
  create_note_if_missing "user2-note-1" "First lab note owned by user2" "$user2_id"
  create_note_if_missing "user2-note-2" "Second lab note owned by user2" "$user2_id"
}

# Peers of the same role for authz -peers (P5.6): user3, an Editor like
# user2, a user_created field on notes (Directus fills it with the caller),
# a create permission for the Editor policy, and notes each peer created
# itself. Directus 12.6.1 refuses custom permission rules (a read filter on
# user_created), so the Editors' read of notes stays open: the lab shows the
# "shared" case. Idempotent.
setup_directus_peers() {
  echo "Directus peers (user3, user_created on notes)..."
  local login_payload token auth_hdr
  login_payload="$(json_eval 'import json,sys; print(json.dumps({"email":"admin@example.com","password":sys.argv[1]}))' "$LAB_ADMIN_PASSWORD")"
  http_call POST "${DIRECTUS_URL}/auth/login" "$login_payload"
  require_status "200" "Directus POST /auth/login (peers)"
  token="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(json.load(sys.stdin)["data"]["access_token"])')"
  auth_hdr="Authorization: Bearer ${token}"

  http_call GET "${DIRECTUS_URL}/fields/notes/user_created" "" "$auth_hdr"
  if [ "$RESP_CODE" != "200" ]; then
    http_call POST "${DIRECTUS_URL}/fields/notes" '{"field":"user_created","type":"uuid","meta":{"special":["user-created"],"interface":"select-dropdown-m2o","readonly":true,"hidden":true},"schema":{}}' "$auth_hdr"
    require_status "200 204" "Directus POST /fields/notes (user_created)"
    echo "Added notes.user_created."
  fi

  local role_id policy_id
  http_call GET "${DIRECTUS_URL}/roles?filter%5Bname%5D%5B_eq%5D=Editor" "" "$auth_hdr"
  role_id="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(json.load(sys.stdin)["data"][0]["id"])')"
  http_call GET "${DIRECTUS_URL}/policies?filter%5Bname%5D%5B_eq%5D=Editor" "" "$auth_hdr"
  policy_id="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(json.load(sys.stdin)["data"][0]["id"])')"
  http_call GET "${DIRECTUS_URL}/permissions?filter%5Bpolicy%5D%5B_eq%5D=${policy_id}&filter%5Bcollection%5D%5B_eq%5D=notes&filter%5Baction%5D%5B_eq%5D=create" "" "$auth_hdr"
  if [ "$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(len(json.load(sys.stdin)["data"]))')" = "0" ]; then
    http_call POST "${DIRECTUS_URL}/permissions" "$(json_eval 'import json,sys; print(json.dumps({"policy":sys.argv[1],"collection":"notes","action":"create","fields":["*"],"permissions":{}}))' "$policy_id")" "$auth_hdr"
    require_status "200 204" "Directus POST /permissions (notes create)"
    echo "Granted Editor create on notes."
  fi

  http_call GET "${DIRECTUS_URL}/users?filter%5Bemail%5D%5B_eq%5D=user3%40example.com" "" "$auth_hdr"
  if [ "$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(len(json.load(sys.stdin)["data"]))')" = "0" ]; then
    http_call POST "${DIRECTUS_URL}/users" "$(json_eval 'import json,sys; print(json.dumps({"email":"user3@example.com","password":sys.argv[1],"role":sys.argv[2],"status":"active"}))' "$LAB_USER2_PASSWORD" "$role_id")" "$auth_hdr"
    require_status "200 204" "Directus POST /users (user3)"
    echo "Created Directus user3@example.com."
  fi

  local u ut titles n
  for u in user2 user3; do
    http_call POST "${DIRECTUS_URL}/auth/login" "$(json_eval 'import json,sys; print(json.dumps({"email":sys.argv[1]+"@example.com","password":sys.argv[2]}))' "$u" "$LAB_USER2_PASSWORD")"
    require_status "200" "Directus POST /auth/login (${u})"
    ut="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(json.load(sys.stdin)["data"]["access_token"])')"
    http_call GET "${DIRECTUS_URL}/items/notes?limit=-1&fields=title" "" "Authorization: Bearer ${ut}"
    require_status "200" "Directus GET /items/notes (${u})"
    titles="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print("\n".join(str(x.get("title","")) for x in json.load(sys.stdin)["data"]))')"
    for n in 1 2; do
      if printf '%s\n' "$titles" | grep -qxF "${u} private note ${n}"; then
        continue
      fi
      http_call POST "${DIRECTUS_URL}/items/notes" "$(json_eval 'import json,sys,secrets; print(json.dumps({"title":sys.argv[1],"body":"secret of "+sys.argv[2]+": "+sys.argv[2].upper()+"-ACCT-"+secrets.token_hex(6)}))' "${u} private note ${n}" "$u")" "Authorization: Bearer ${ut}"
      require_status "200 204" "Directus POST /items/notes (${u} note ${n})"
      echo "Created '${u} private note ${n}' as ${u}."
    done
  done
}

# Jellyfin user3, a non-admin peer of user2 (P5.6). Idempotent.
setup_jellyfin_peers() {
  echo "Jellyfin peers (user3)..."
  local auth_payload tok emby_auth
  auth_payload="$(json_eval 'import json,sys; print(json.dumps({"Username":"admin","Pw":sys.argv[1]}))' "$LAB_ADMIN_PASSWORD")"
  local i
  for i in $(seq 1 30); do # after the https restart the server answers 503 while it loads
    http_call POST "${JELLYFIN_URL}/Users/AuthenticateByName" "$auth_payload" "Authorization: ${EMBY_AUTH_BASE}"
    [ "$RESP_CODE" = "503" ] || break
    sleep 2
  done
  require_status "200" "Jellyfin POST /Users/AuthenticateByName (peers)"
  tok="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(json.load(sys.stdin)["AccessToken"])')"
  emby_auth="${EMBY_AUTH_BASE}, Token=\"${tok}\""
  http_call GET "${JELLYFIN_URL}/Users" "" "Authorization: ${emby_auth}"
  require_status "200" "Jellyfin GET /Users (peers)"
  if [ -z "$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys
print("".join(u.get("Id","") for u in json.load(sys.stdin) if u.get("Name")=="user3"))')" ]; then
    http_call POST "${JELLYFIN_URL}/Users/New" "$(json_eval 'import json,sys; print(json.dumps({"Name":"user3","Password":sys.argv[1]}))' "$LAB_USER2_PASSWORD")" "Authorization: ${emby_auth}"
    require_status "200 201" "Jellyfin POST /Users/New (user3)"
    echo "Created Jellyfin user3."
  fi
}

write_credentials() {
  ensure_gitignore
  umask 077
  cat > "$CREDS_FILE" <<EOF
# Generated by testbed/lab/setup.sh
JELLYFIN_URL=https://jellyfin.jsh.test:8920
JELLYFIN_IP_URL=${JELLYFIN_URL}
JELLYFIN_ADMIN_USER=admin
JELLYFIN_ADMIN_PASSWORD=${LAB_ADMIN_PASSWORD}
JELLYFIN_USER2_USER=user2
JELLYFIN_USER2_PASSWORD=${LAB_USER2_PASSWORD}
JELLYFIN_USER3_USER=user3
JELLYFIN_USER3_PASSWORD=${LAB_USER2_PASSWORD}

DIRECTUS_URL=http://directus.jsh.test:8055
DIRECTUS_IP_URL=${DIRECTUS_URL}
DIRECTUS_ADMIN_EMAIL=admin@example.com
DIRECTUS_ADMIN_PASSWORD=${LAB_ADMIN_PASSWORD}
DIRECTUS_USER2_EMAIL=user2@example.com
DIRECTUS_USER2_PASSWORD=${LAB_USER2_PASSWORD}
DIRECTUS_USER3_EMAIL=user3@example.com
DIRECTUS_USER3_PASSWORD=${LAB_USER2_PASSWORD}
EOF
  chmod 600 "$CREDS_FILE"
  echo "Wrote credentials to ${CREDS_FILE} (mode 600)."
}

# Jellyfin Web needs a secure context (crypto.randomUUID): it is served over
# https on 8920 with a self-signed certificate made here (jsharvest login and
# crawl take -insecure). Idempotent: an https port that answers is kept.
setup_jellyfin_https() {
  if curl -sk -o /dev/null --max-time 3 "https://172.31.250.10:8920/System/Info/Public"; then
    echo "Jellyfin https already on 8920."
    return 0
  fi
  echo "Enabling Jellyfin https on 8920 (self-signed)..."
  local tmp
  tmp="$(mktemp -d)"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp/k.pem" -out "$tmp/c.pem" -days 365 \
    -subj "/CN=jellyfin.jsh.test" -addext "subjectAltName=DNS:jellyfin.jsh.test" 2>/dev/null || die "openssl req failed"
  openssl pkcs12 -export -out "$tmp/cert.pfx" -inkey "$tmp/k.pem" -in "$tmp/c.pem" -passout pass: 2>/dev/null || die "openssl pkcs12 failed"
  chmod 644 "$tmp/cert.pfx" # the container's user reads it (no capabilities)
  docker cp "$tmp/cert.pfx" jshlab-jellyfin-1:/config/cert.pfx >/dev/null || die "docker cp of the certificate failed"
  rm -rf "$tmp"
  local auth_payload
  auth_payload="$(json_eval 'import json,sys; print(json.dumps({"Username":"admin","Pw":sys.argv[1]}))' "$LAB_ADMIN_PASSWORD")"
  http_call POST "${JELLYFIN_URL}/Users/AuthenticateByName" "$auth_payload" "Authorization: ${EMBY_AUTH_BASE}"
  require_status "200" "Jellyfin POST /Users/AuthenticateByName (https)"
  local tok emby_auth
  tok="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys; print(json.load(sys.stdin)["AccessToken"])')"
  emby_auth="${EMBY_AUTH_BASE}, Token=\"${tok}\""
  http_call GET "${JELLYFIN_URL}/System/Configuration/network" "" "Authorization: ${emby_auth}"
  require_status "200" "Jellyfin GET /System/Configuration/network"
  local net
  net="$(printf '%s' "$RESP_BODY" | json_eval 'import json,sys
c=json.load(sys.stdin); c.update(EnableHttps=True, CertificatePath="/config/cert.pfx", CertificatePassword="", InternalHttpsPort=8920)
print(json.dumps(c))')"
  http_call POST "${JELLYFIN_URL}/System/Configuration/network" "$net" "Authorization: ${emby_auth}"
  require_status "200 204" "Jellyfin POST /System/Configuration/network"
  docker restart jshlab-jellyfin-1 >/dev/null || die "docker restart jellyfin failed"
  local i
  for i in $(seq 1 30); do
    curl -sk -o /dev/null --max-time 2 "https://172.31.250.10:8920/System/Info/Public" && { echo "Jellyfin https is up."; return 0; }
    sleep 2
  done
  die "Jellyfin https did not come up on 8920"
}

main() {
  setup_jellyfin
  setup_jellyfin_https
  setup_jellyfin_peers
  setup_directus
  setup_directus_peers
  write_credentials
  echo ""
  echo "Lab setup complete."
  echo "Use Chrome -host-resolver-rules:"
  echo "  MAP jellyfin.jsh.test 172.31.250.10, MAP directus.jsh.test 172.31.250.11"
}

main "$@"
