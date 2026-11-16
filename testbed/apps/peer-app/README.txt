peer-app (plan-28 P5.3; docs/gd7-bola-design.md 6): the fixture of authz -peers, served by
testbed/cmd/testbed (peer.go) under /api/peer/, the page from dist/.
People: alice, bob (org-alpha); charlie, dave (org-beta, dave owns nothing).
Login: POST /api/peer/login (form or JSON: user, password); the password of all four
is PEER_PASS=hunter22 (a test value). Steps: login-<user>.steps.json.
POST /api/peer/_phase?p=replay tells the server the crawl is over (quota expires for all);
GET /api/peer/_phase says the phase and the keys regenerated. PEER_PHASE=replay starts there.
The server log has PEERLOG user=... lines (who asked) besides the usual "STATUS METHOD URI".
peer.truth.json: what authz -peers must conclude, by scenario (testbed peerscore).
secrets.txt: the strings of each person's data that may not leak into bola.json/bola.md.
Case 11 (keys?action=regenerate) is sent by a click on #regen; bola-check.sh checks the crawl recorded it.
