package explore

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/cdp"
)

// tree builds a page by hand: every element is rendered and visible unless
// a test says otherwise.
type tree struct{ p *Page }

func newTree(url string) *tree {
	t := &tree{p: &Page{URL: url, Docs: []Doc{{URL: url, Frame: "F", Root: 0}}}}
	t.p.Nodes = append(t.p.Nodes, Node{Parent: -1, Type: 9, Backend: 1, Box: &Rect{800, 600}, Visible: true})
	return t
}

// el adds an element under parent, with attributes as name, value pairs.
func (t *tree) el(parent int, tag string, attrs ...string) int {
	a := map[string]string{}
	for i := 0; i+1 < len(attrs); i += 2 {
		a[attrs[i]] = attrs[i+1]
	}
	n := Node{Parent: parent, Type: 1, Tag: tag, Attrs: a, Backend: cdp.BackendNodeID(len(t.p.Nodes) + 1),
		Box: &Rect{100, 20}, Visible: true, Cursor: "auto", Doc: t.p.Nodes[max(parent, 0)].Doc}
	switch tag {
	case "a", "button", "input", "select", "textarea", "summary":
		n.Clickable = tag != "a" || a["href"] != ""
	}
	t.p.Nodes = append(t.p.Nodes, n)
	return len(t.p.Nodes) - 1
}

func (t *tree) text(parent int, s string) {
	t.p.Nodes = append(t.p.Nodes, Node{Parent: parent, Type: 3, Text: s, Backend: cdp.BackendNodeID(len(t.p.Nodes) + 1), Doc: t.p.Nodes[parent].Doc})
}

func (t *tree) on(n int, types ...string) {
	t.p.Nodes[n].Listeners = append(t.p.Nodes[n].Listeners, types...)
}

func (t *tree) candidates() ([]Candidate, map[string]int) {
	t.p.index()
	return Candidates(t.p)
}

// got lists the candidates as "action label", in order.
func got(cs []Candidate) []string {
	var out []string
	for _, c := range cs {
		out = append(out, string(c.Action)+" "+c.Label)
	}
	return out
}

func TestDelegatedToRoot(t *testing.T) {
	tr := newTree("http://app.test/")
	body := tr.el(0, "body")
	root := tr.el(body, "div", "id", "root")
	tr.on(root, "click")
	for _, name := range []string{"Open card A", "Open card B"} {
		card := tr.el(root, "div", "class", "card")
		tr.p.Nodes[card].Cursor = "pointer"
		inner := tr.el(card, "span")
		tr.p.Nodes[inner].Cursor = "pointer" // inherited: not a card of its own
		tr.text(inner, name)
	}
	plain := tr.el(root, "p")
	tr.text(plain, "not clickable")
	cs, _ := tr.candidates()
	if want := []string{"click Open card A", "click Open card B"}; !slices.Equal(got(cs), want) {
		t.Fatalf("got %v, want %v: the cards, not the root they delegate to, nor their inner spans", got(cs), want)
	}
}

func TestHoverMenuWithHiddenItem(t *testing.T) {
	tr := newTree("http://app.test/")
	menu := tr.el(0, "div", "id", "menu")
	tr.on(menu, "mouseenter", "mouseleave")
	tr.text(menu, "Menu")
	item := tr.el(menu, "button", "id", "reports", "hidden", "")
	tr.p.Nodes[item].Visible, tr.p.Nodes[item].Box = false, nil
	tr.text(item, "Reports")
	cs, _ := tr.candidates()
	if want := []string{"hover Menu"}; !slices.Equal(got(cs), want) {
		t.Fatalf("got %v, want %v", got(cs), want)
	}
	// Once shown, the item is clicked, and the menu is a container.
	tr.p.Nodes[item].Visible, tr.p.Nodes[item].Box = true, &Rect{50, 20}
	cs, _ = tr.candidates()
	if want := []string{"click Reports"}; !slices.Equal(got(cs), want) {
		t.Fatalf("got %v, want %v", got(cs), want)
	}
}

func TestContainerAndCardWithLink(t *testing.T) {
	tr := newTree("http://app.test/")
	ul := tr.el(0, "ul", "id", "items")
	tr.on(ul, "click")
	for _, id := range []string{"42", "108"} {
		li := tr.el(ul, "li")
		b := tr.el(li, "button", "class", "open", "data-id", id)
		tr.text(b, "Open")
	}
	// A card with a handler of its own and a plain link inside: the card
	// is clicked (the link is the frontier's).
	card := tr.el(0, "div", "class", "card")
	tr.on(card, "click")
	tr.text(card, "Card")
	tr.el(card, "a", "href", "/more")
	cs, _ := tr.candidates()
	if want := []string{"click Open", "click Open", "click Card"}; !slices.Equal(got(cs), want) {
		t.Fatalf("got %v, want %v", got(cs), want)
	}
	if cs[0].Sig != cs[1].Sig {
		t.Fatalf("rows alike, signatures apart: %q %q", cs[0].Sig, cs[1].Sig)
	}
}

func TestSessionEnd(t *testing.T) {
	tr := newTree("http://app.test/")
	for _, a := range [][]string{
		{"id", "logout-btn"}, {"aria-label", "Sign out"}, {"class", "btnLogout"}, {"id", "logoutButton"}, {"data-action", "end_session"},
	} {
		b := tr.el(0, "button", a...)
		tr.text(b, "x")
	}
	keep := tr.el(0, "button", "id", "catalogOutput")
	tr.text(keep, "Catalog output")
	blog := tr.el(0, "button")
	tr.text(blog, "Blog outline")
	form := tr.el(0, "form", "action", "/auth/logout")
	sub := tr.el(form, "button")
	tr.text(sub, "Go")
	cs, skipped := tr.candidates()
	if want := []string{"click Catalog output", "click Blog outline"}; !slices.Equal(got(cs), want) {
		t.Fatalf("got %v, want %v", got(cs), want)
	}
	if skipped[SessionEnd] != 6 {
		t.Fatalf("skipped %v", skipped)
	}
}

func TestDisabledAndInert(t *testing.T) {
	tr := newTree("http://app.test/")
	tr.text(tr.el(0, "button", "disabled", ""), "Off")
	fs := tr.el(0, "fieldset", "disabled", "")
	tr.text(tr.el(fs, "button"), "In a disabled fieldset")
	tr.text(tr.el(tr.el(0, "div", "inert", ""), "button"), "Inert")
	tr.text(tr.el(0, "div", "role", "button", "aria-disabled", "true"), "ARIA off")
	hidden := tr.el(0, "button")
	tr.text(hidden, "Hidden")
	tr.p.Nodes[hidden].Visible = false
	tr.text(tr.el(0, "button"), "On")
	cs, _ := tr.candidates()
	if want := []string{"click On"}; !slices.Equal(got(cs), want) {
		t.Fatalf("got %v, want %v", got(cs), want)
	}
}

func TestForms(t *testing.T) {
	tr := newTree("http://app.test/")
	f := tr.el(0, "form", "action", "/signup")
	tr.el(f, "input", "name", "email", "type", "email", "placeholder", "email")
	filled := tr.el(f, "input", "name", "nick")
	tr.p.Nodes[filled].Value = "Bob"
	tr.el(f, "input", "type", "checkbox", "name", "terms")
	tr.el(f, "select", "name", "plan")
	tr.el(f, "input", "type", "file", "name", "avatar")
	tr.el(f, "input", "type", "hidden", "name", "csrf")
	tr.text(tr.el(f, "button"), "Create")
	// A form with no button is sent with Enter.
	g := tr.el(0, "form", "id", "find")
	tr.el(g, "input", "name", "q")
	// A field with a key listener outside any form.
	quick := tr.el(0, "input", "id", "quick", "placeholder", "Quick search")
	tr.on(quick, "keydown")
	cs, _ := tr.candidates()
	want := []string{"type email", "check terms", "select plan", "upload avatar", "submit Create", "type q", "type Quick search", "key Quick search", "key q"}
	if !slices.Equal(got(cs), want) {
		t.Fatalf("got %v\nwant %v", got(cs), want)
	}
}

func TestLinks(t *testing.T) {
	tr := newTree("http://app.test/")
	tr.text(tr.el(0, "a", "href", "/about"), "About")
	pre := tr.el(0, "a", "href", "/docs")
	tr.on(pre, "mouseenter")
	tr.text(pre, "Docs")
	hash := tr.el(0, "a", "href", "#")
	tr.on(hash, "click")
	tr.text(hash, "Hash")
	tr.text(tr.el(0, "a", "href", "javascript:void(0)", "onclick", "go()"), "JS")
	cs, _ := tr.candidates()
	if want := []string{"hover Docs", "click Hash", "click JS"}; !slices.Equal(got(cs), want) {
		t.Fatalf("got %v, want %v", got(cs), want)
	}
}

func TestSignatures(t *testing.T) {
	tr := newTree("http://app.test/list")
	bar := tr.el(0, "div", "class", "toolbar")
	for _, l := range []string{"Save", "Archive", "Share"} {
		tr.text(tr.el(bar, "button", "class", "btn tool"), l)
	}
	more := tr.el(0, "div", "id", "more")
	tr.text(tr.el(more, "button", "class", "load-more"), "Show 10 more")
	tr.text(tr.el(more, "button", "class", "load-more"), "Show 20 more")
	tr.text(tr.el(0, "button", "id", "row-41"), "View")
	tr.text(tr.el(0, "button", "id", "row-42"), "View")
	cs, _ := tr.candidates()
	sigs := map[string]int{}
	for _, c := range cs {
		sigs[c.Sig]++
	}
	if len(sigs) != 5 {
		var lines []string
		for s, n := range sigs {
			lines = append(lines, fmt.Sprintf("%d %s", n, s))
		}
		t.Fatalf("want 5 signatures (three tools, one load more, one row), got:\n%s", strings.Join(lines, "\n"))
	}
	// The same toolbar on another route of the app is the same thing to do.
	other := *tr.p
	other.URL = "http://app.test/settings"
	cs2, _ := Candidates(&other)
	if cs2[0].Sig != cs[0].Sig {
		t.Fatal("the page's path is no context")
	}
}

func TestFrameAndShadow(t *testing.T) {
	tr := newTree("http://app.test/")
	frame := tr.el(0, "iframe", "src", "/frame.html")
	host := tr.el(0, "x-widget")
	shadow := len(tr.p.Nodes)
	tr.p.Nodes = append(tr.p.Nodes, Node{Parent: host, Type: 11, Shadow: true, Backend: 99, Visible: false})
	b := tr.el(shadow, "button")
	tr.on(b, "click")
	tr.text(b, "Widget action")
	// The frame's document, as the snapshot gives it: a document of its
	// own, under the frame element.
	tr.p.Docs = append(tr.p.Docs, Doc{URL: "http://app.test/frame.html", Frame: "F2", Root: len(tr.p.Nodes)})
	tr.p.Nodes = append(tr.p.Nodes, Node{Parent: frame, Type: 9, Doc: 1, Backend: 100})
	fb := tr.el(len(tr.p.Nodes)-1, "button")
	tr.text(fb, "Frame action")
	cs, _ := tr.candidates()
	if want := []string{"click Widget action", "click Frame action"}; !slices.Equal(got(cs), want) {
		t.Fatalf("got %v, want %v", got(cs), want)
	}
	if cs[1].Frame != "F2" || !strings.Contains(cs[1].Sig, "@/frame.html") {
		t.Fatalf("frame candidate %+v", cs[1])
	}
	if !tr.p.Contains(frame, fb) || !tr.p.Contains(host, b) {
		t.Fatal("Contains does not cross frames and shadow roots")
	}
}

func sigCount(cs []Candidate) int {
	m := map[string]bool{}
	for _, c := range cs {
		m[c.Sig] = true
	}
	return len(m)
}

func TestRowsCollapseMenusDoNot(t *testing.T) {
	// Table rows named after their data, clickable as a whole.
	tr := newTree("http://app.test/")
	tbody := tr.el(0, "tbody")
	for _, name := range []string{"Alice", "Bob", "Carol", "Dave"} {
		row := tr.el(tbody, "tr", "class", "row")
		tr.on(row, "click")
		tr.text(tr.el(row, "td"), name)
	}
	cs, _ := tr.candidates()
	if len(cs) != 4 || sigCount(cs) != 1 {
		t.Fatalf("rows: %d candidates, %d signatures: %v", len(cs), sigCount(cs), got(cs))
	}
	// List items: text and a button named after the item.
	tr = newTree("http://app.test/")
	ul := tr.el(0, "ul", "id", "invoices")
	for _, n := range []string{"INV-A", "INV-B", "INV-C"} {
		li := tr.el(ul, "li")
		tr.text(li, "Invoice "+n+" due soon")
		tr.text(tr.el(li, "button", "class", "view"), "View "+n)
	}
	cs, _ = tr.candidates()
	if sigCount(cs) != 1 {
		t.Fatalf("list items: %v", got(cs))
	}
	// A menu: each item holds only its button.
	tr = newTree("http://app.test/")
	menu := tr.el(0, "ul", "class", "menu")
	for _, n := range []string{"Profile", "Settings", "Billing"} {
		tr.text(tr.el(tr.el(menu, "li"), "button"), n)
	}
	cs, _ = tr.candidates()
	if sigCount(cs) != 3 {
		t.Fatalf("menu: %d signatures for %v", sigCount(cs), got(cs))
	}
}

func TestCardsAndLinkHandlers(t *testing.T) {
	tr := newTree("http://app.test/")
	card := tr.el(0, "div", "class", "card")
	tr.on(card, "click")
	tr.text(tr.el(card, "h3"), "Plan Pro")
	like := tr.el(card, "button")
	tr.on(like, "click")
	tr.text(like, "Like")
	modal := tr.el(0, "a", "href", "/terms")
	tr.on(modal, "click")
	tr.text(modal, "Terms")
	cs, _ := tr.candidates()
	if want := []string{"click Plan Pro Like", "click Like", "click Terms"}; !slices.Equal(got(cs), want) {
		t.Fatalf("got %v, want %v", got(cs), want)
	}
}

func TestSessionEndMore(t *testing.T) {
	tr := newTree("http://app.test/")
	tr.text(tr.el(0, "button"), "Đăng xuất")
	tr.text(tr.el(0, "button"), "Thoát")
	icon := tr.el(0, "button", "title", "")
	tr.el(icon, "i", "class", "fa fa-sign-out")
	svg := tr.el(0, "button")
	tr.el(tr.el(svg, "svg"), "use", "href", "#icon-logout")
	tr.text(tr.el(0, "button", "data-testid", "user-menu-logout"), "x")
	tr.text(tr.el(0, "button"), "Thoáng mát") // not a logout
	cs, skipped := tr.candidates()
	if want := []string{"click Thoáng mát"}; !slices.Equal(got(cs), want) || skipped[SessionEnd] != 5 {
		t.Fatalf("got %v, skipped %v", got(cs), skipped)
	}
}

func TestContexts(t *testing.T) {
	tr := newTree("http://app.test/settings")
	body := tr.el(0, "body")
	root := tr.el(body, "div", "id", "root") // the app's mount point
	for _, fields := range [][]string{{"email", "name"}, {"password", "password2"}} {
		f := tr.el(root, "form")
		for _, n := range fields {
			tr.p.Nodes[tr.el(f, "input", "name", n)].Value = "x"
		}
		tr.text(tr.el(f, "button"), "Save")
	}
	tr.text(tr.el(root, "button", "class", "help"), "Help")
	cs, _ := tr.candidates()
	if sigCount(cs) != 3 || !strings.Contains(cs[0].Sig, "form:email,name") {
		t.Fatalf("%d signatures: %q", sigCount(cs), cs[0].Sig)
	}
	if !strings.Contains(cs[2].Sig, "#root") {
		t.Fatalf("context: %q", cs[2].Sig)
	}
}

func TestOnlyWhatIsHeard(t *testing.T) {
	tr := newTree("http://app.test/")
	dbl := tr.el(0, "div", "id", "dbl")
	tr.on(dbl, "dblclick")
	tr.text(dbl, "Double")
	ctx := tr.el(0, "div", "id", "ctx")
	tr.on(ctx, "contextmenu")
	tr.text(ctx, "Right")
	both := tr.el(0, "div", "id", "both")
	tr.on(both, "click", "mouseenter")
	tr.text(both, "Both")
	cs, _ := tr.candidates()
	if want := []string{"dblclick Double", "contextmenu Right", "hover Both", "click Both"}; !slices.Equal(got(cs), want) {
		t.Fatalf("got %v, want %v", got(cs), want)
	}
}

// Two cards in one container that sits among many plain siblings: the
// container is no row, and the cards keep their names.
func TestCardsInOneContainer(t *testing.T) {
	tr := newTree("http://app.test/")
	main := tr.el(0, "main", "id", "main")
	for range 4 {
		tr.el(main, "div")
	}
	root := tr.el(main, "div")
	tr.on(root, "click")
	for _, n := range []string{"Open card A", "Open card B"} {
		c := tr.el(root, "div", "class", "card")
		tr.p.Nodes[c].Cursor = "pointer"
		tr.text(c, n)
	}
	cs, _ := tr.candidates()
	if len(cs) != 2 || sigCount(cs) != 2 {
		t.Fatalf("%v: %d signatures", got(cs), sigCount(cs))
	}
}

// Plain sections alike are no rows: their buttons keep their names, and two
// whose ids differ by a digit stay apart.
func TestSectionsAreNoRows(t *testing.T) {
	tr := newTree("http://app.test/")
	body := tr.el(0, "body")
	for _, labels := range [][]string{{"Search"}, {"Wizard: next", "Wizard: finish"}, {"Export"}, {"Report"}} {
		sec := tr.el(body, "section")
		for k, l := range labels {
			tr.text(tr.el(sec, "button", "id", fmt.Sprintf("b%d", k+1)), l)
		}
	}
	cs, _ := tr.candidates()
	if len(cs) != 5 || sigCount(cs) != 5 {
		t.Fatalf("%v: %d signatures", got(cs), sigCount(cs))
	}
}
