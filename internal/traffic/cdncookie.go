package traffic

import "strings"

// CDNCookie reports whether a cookie is a CDN's or a bot manager's, not
// the application's: Cloudflare's (__cf_bm, cf_clearance…), Akamai's
// (_abck, bm_sz…), DataDome's, HUMAN/PerimeterX's, Imperva's. A browser
// keeps them as it goes; they say nothing of who is logged in, and a
// replay neither takes them for a session's nor sends one role's with
// another's (round 25K).
func CDNCookie(name string) bool {
	switch name {
	case "__cf_bm", "cf_clearance", "__cflb", "_cfuvid", "__cfruid", "__cfwaitingroom", "cf_chl_rc_m", "cf_chl_2",
		"_abck", "bm_sz", "bm_sv", "bm_mi", "ak_bmsc", "bm_so", "bm_lso",
		"datadome", "reese84":
		return true
	}
	for _, p := range []string{"_px", "incap_ses_", "visid_incap_", "nlbi_", "cf_chl_"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
