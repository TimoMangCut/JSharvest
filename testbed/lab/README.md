# Local Isolated Lab (`testbed/lab`)

Isolated Docker Compose lab running **Jellyfin** and **Directus (SQLite)** on an `internal: true` bridge (`172.31.250.0/24`) with no published ports and two local accounts per app, for `jsharvest` testing.

## Pinned Images

- Jellyfin (`172.31.250.10:8096`):
  `jellyfin/jellyfin:12.4.20261026-211555@sha256:fea863d0cd9ec445985d9c75fc6ed64e38a1d2766cf0c250a33d553f4fc1b771`
- Directus (`172.31.250.11:8055`):
  `directus/directus:12.6.1@sha256:e1561b5e526e8e7a2ac19b7bb6eab63611dd84a862a8c45b864118768a2baff4`

## Usage

1. Bring up the lab:
   ```bash
   docker compose -f testbed/lab/compose.yml up -d
   ```

2. Run idempotent setup (creates accounts, Directus `Editor` role/policy & `notes` items, disables Jellyfin plugin repos, writes `testbed/lab/.lab-credentials`):
   ```bash
   bash testbed/lab/setup.sh
   ```

3. Check network isolation:
   ```bash
   bash testbed/lab/check-isolation.sh
   ```

4. Tear down (including named volumes):
   ```bash
   docker compose -f testbed/lab/compose.yml down -v
   ```

## Chrome Host Resolver Rules

Pass to Chrome / `jsharvest`:

```text
MAP jellyfin.jsh.test 172.31.250.10, MAP directus.jsh.test 172.31.250.11
```

## Jellyfin over https

Jellyfin Web needs a secure context (`crypto.randomUUID`), which
`http://jellyfin.jsh.test:8096` is not, so its login page never logs in.
`setup.sh` makes a self-signed certificate and serves Jellyfin on
`https://jellyfin.jsh.test:8920` (also its published URL, or the page would
call http from https). `jsharvest login` and `crawl` take `-insecure` for it,
and log in from the origin (`-u https://jellyfin.jsh.test:8920/`): the
login keeps its token in localStorage, not in a cookie.

## Peers for authz -peers

`setup.sh` also makes `user3` (Directus Editor, like `user2`; Jellyfin
non-admin, like `user2`), a `user_created` field on `notes`, and two notes
each peer creates itself. Directus 12.6.1 refuses custom permission rules,
so the Editors read every note: the lab shows the `shared` case, not an
owner check. Credentials: `*_USER3_*` in `.lab-credentials`.
