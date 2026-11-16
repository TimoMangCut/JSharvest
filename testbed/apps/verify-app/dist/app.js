// verify-app (testbed/verify-check.sh, gate 18): the routes jsharvest verify
// is asked of are the server's (testbed/cmd/testbed/verifyapp.go); this
// page is for testbed/bench.sh.
var MARK = "JSHMARK:verify:app";
fetch("/api/v1/items");
