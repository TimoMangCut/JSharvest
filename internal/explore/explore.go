// Package explore picks what a crawler can do on a page as a person would:
// the elements to click, type into, choose, hover or submit, one of each
// kind, from a snapshot of the page's DOM, layout, styles and event
// listeners. It is pure: the engine takes the snapshot and acts.
package explore

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/domsnapshot"
)

// Node is one node of a page's snapshot, documents of frames included.
type Node struct {
	Backend   cdp.BackendNodeID
	Parent    int // index in Page.Nodes; -1 for the top document
	Doc       int // index in Page.Docs
	Type      int64
	Tag       string // lower case; elements only
	Attrs     map[string]string
	Text      string // a text node's value
	Value     string // an input's or a textarea's value
	Checked   bool
	Shadow    bool // a shadow root
	Box       *Rect
	Cursor    string
	Visible   bool // rendered, and not hidden or out of the pointer's reach by style
	Clickable bool // Chrome's own view: a click listener, a link, a form control
	Listeners []string
	Children  []int
}

type Rect struct{ W, H float64 }

// Doc is one document of the snapshot: the page's, or a frame's.
type Doc struct {
	URL   string
	Frame string
	Root  int
}

type Page struct {
	URL   string
	Nodes []Node
	Docs  []Doc
	byID  []map[string]int // per document: element id -> node
}

// Styles are the computed styles a snapshot must be taken with, in this
// order.
var Styles = []string{"cursor", "visibility", "display", "pointer-events"}

// FromSnapshot builds a Page from DOMSnapshot.captureSnapshot, taken with
// Styles, and the event listeners of each node by backend id.
func FromSnapshot(snap *domsnapshot.CaptureSnapshotResult, listeners map[cdp.BackendNodeID][]string) *Page {
	p := &Page{}
	str := func(i domsnapshot.StringIndex) string {
		if i < 0 || int(i) >= len(snap.Strings) {
			return ""
		}
		return snap.Strings[i]
	}
	type owner struct{ node, doc int }
	var owners []owner // iframe elements and the documents they hold
	for di, d := range snap.Documents {
		nodes := d.Nodes
		if nodes == nil {
			continue
		}
		base := len(p.Nodes)
		p.Docs = append(p.Docs, Doc{URL: str(d.DocumentURL), Frame: str(d.FrameID), Root: base})
		n := len(nodes.NodeType)
		for i := 0; i < n; i++ {
			nd := Node{Parent: -1, Doc: di, Type: nodes.NodeType[i]}
			if i < len(nodes.ParentIndex) && nodes.ParentIndex[i] >= 0 {
				nd.Parent = base + int(nodes.ParentIndex[i])
			}
			if i < len(nodes.BackendNodeID) {
				nd.Backend = nodes.BackendNodeID[i]
			}
			switch nd.Type {
			case 1:
				nd.Tag = strings.ToLower(str(nodes.NodeName[i]))
				nd.Attrs = map[string]string{}
				if i < len(nodes.Attributes) {
					a := nodes.Attributes[i]
					for j := 0; j+1 < len(a); j += 2 {
						nd.Attrs[strings.ToLower(str(domsnapshot.StringIndex(a[j])))] = str(domsnapshot.StringIndex(a[j+1]))
					}
				}
			case 3:
				if i < len(nodes.NodeValue) {
					nd.Text = str(nodes.NodeValue[i])
				}
			}
			nd.Listeners = listeners[nd.Backend]
			p.Nodes = append(p.Nodes, nd)
		}
		rare := func(r *domsnapshot.RareStringData, set func(*Node, string)) {
			if r == nil {
				return
			}
			for k, i := range r.Index {
				if int(i) < n && k < len(r.Value) {
					set(&p.Nodes[base+int(i)], str(r.Value[k]))
				}
			}
		}
		rare(nodes.InputValue, func(nd *Node, v string) { nd.Value = v })
		rare(nodes.TextValue, func(nd *Node, v string) { nd.Value = v })
		rare(nodes.ShadowRootType, func(nd *Node, v string) { nd.Shadow = v != "" })
		if nodes.InputChecked != nil {
			for _, i := range nodes.InputChecked.Index {
				p.Nodes[base+int(i)].Checked = true
			}
		}
		if nodes.IsClickable != nil {
			for _, i := range nodes.IsClickable.Index {
				p.Nodes[base+int(i)].Clickable = true
			}
		}
		if cd := nodes.ContentDocumentIndex; cd != nil {
			for k, i := range cd.Index {
				if k < len(cd.Value) {
					owners = append(owners, owner{base + int(i), int(cd.Value[k])})
				}
			}
		}
		if l := d.Layout; l != nil {
			for k, ni := range l.NodeIndex {
				nd := &p.Nodes[base+int(ni)]
				if k < len(l.Bounds) && len(l.Bounds[k]) == 4 {
					b := l.Bounds[k]
					nd.Box = &Rect{b[2], b[3]}
				}
				style := map[string]string{}
				if k < len(l.Styles) {
					for si, v := range l.Styles[k] {
						if si < len(Styles) {
							style[Styles[si]] = str(domsnapshot.StringIndex(v))
						}
					}
				}
				nd.Cursor = style["cursor"]
				nd.Visible = nd.Box != nil && nd.Box.W >= 1 && nd.Box.H >= 1 &&
					style["visibility"] != "hidden" && style["visibility"] != "collapse" &&
					style["display"] != "none" && style["pointer-events"] != "none"
			}
		}
	}
	// A frame's document hangs under the frame element.
	for _, o := range owners {
		if o.doc < len(p.Docs) && o.doc > 0 {
			p.Nodes[p.Docs[o.doc].Root].Parent = o.node
		}
	}
	p.index()
	return p
}

// index links children to their parents and maps element ids, per
// document.
func (p *Page) index() {
	p.byID = make([]map[string]int, len(p.Docs))
	for i := range p.byID {
		p.byID[i] = map[string]int{}
	}
	for i := range p.Nodes {
		p.Nodes[i].Children = nil
	}
	for i, n := range p.Nodes {
		if n.Parent >= 0 && n.Parent < len(p.Nodes) {
			p.Nodes[n.Parent].Children = append(p.Nodes[n.Parent].Children, i)
		}
		if id := n.Attrs["id"]; id != "" && n.Doc < len(p.byID) {
			if _, dup := p.byID[n.Doc][id]; !dup {
				p.byID[n.Doc][id] = i
			}
		}
	}
	if len(p.Docs) > 0 && p.URL == "" {
		p.URL = p.Docs[0].URL
	}
}

// Contains reports whether node a is node b or one of its ancestors, frame
// and shadow boundaries included.
func (p *Page) Contains(a, b int) bool {
	for n := b; n >= 0 && n < len(p.Nodes); n = p.Nodes[n].Parent {
		if n == a {
			return true
		}
	}
	return false
}

// ByBackend maps backend node ids to nodes.
func (p *Page) ByBackend() map[cdp.BackendNodeID]int {
	m := make(map[cdp.BackendNodeID]int, len(p.Nodes))
	for i, n := range p.Nodes {
		m[n.Backend] = i
	}
	return m
}

// Action is what explore does to an element.
type Action string

const (
	Click       Action = "click"
	DblClick    Action = "dblclick"
	ContextMenu Action = "contextmenu"
	Hover       Action = "hover"
	Type        Action = "type"   // type into an empty field
	Key         Action = "key"    // press Enter in it
	Select      Action = "select" // choose another option
	Check       Action = "check"  // click a checkbox or radio
	Submit      Action = "submit" // click a form's submit button
	Upload      Action = "upload" // give a file input a file
)

// Candidate is one thing explore can do.
type Candidate struct {
	Node     int
	Backend  cdp.BackendNodeID
	Frame    string
	Action   Action
	Tag      string
	Role     string
	Type     string // an input's type
	ID       string
	Label    string
	Selector string
	Sig      string // what it shares with the controls that do the same (see sign)
	Raw      string // this control exactly: digits kept, so a wizard's next field is new
}

// Skip reasons.
const (
	SessionEnd = "session-end" // a logout: the page may end the session with no request to hold back
)

var (
	clickTypes = set("click", "mousedown", "mouseup", "pointerdown", "pointerup", "touchstart", "touchend")
	hoverTypes = set("mouseover", "mouseenter", "pointerover", "pointerenter")
	keyTypes   = set("keydown", "keyup", "keypress")
	roles      = set("button", "link", "tab", "menuitem", "menuitemcheckbox", "menuitemradio", "option", "switch",
		"checkbox", "radio", "treeitem", "combobox")
	// textTypes take typed text; range and color do not (a form's check
	// fills them in when they must be).
	textTypes = set("", "text", "search", "email", "url", "tel", "password", "number", "date", "datetime-local",
		"month", "week", "time")
	inlineHandlers = set("onclick", "ondblclick", "onmousedown", "onmouseup", "onpointerdown", "onpointerup",
		"onmouseover", "onmouseenter", "onkeydown", "onkeyup", "onkeypress", "onchange", "oninput", "oncontextmenu")
	// sessionEndRe names the controls that end a session. The guard holds
	// back the request of a logout, but an app may log out in the page
	// alone (clearing its storage), which nothing can hold back.
	sessionEndRe = regexp.MustCompile(`(?i)(^|[^a-z0-9])(log[-_ ]?out|log[-_ ]?off|sign[-_ ]?out|end[-_ ]?session|switch[-_ ]?(account|user)|wsignout|đăng[-_ ]?xuất|dang[-_ ]?xuat|thoát)([^a-z]|$)`)
	// camelEndRe finds the same words joined to others in camelCase:
	// btnLogout, logoutButton, userSignOut; not catalogOutput.
	camelEndRe = regexp.MustCompile(`(^|[a-z0-9])(Log[Oo]ut|Log[Oo]ff|Sign[Oo]ut)([^a-z]|$)|^(logout|logoff|signout)[A-Z]`)
	digitsRe   = regexp.MustCompile(`\d+`)
	spaceRe    = regexp.MustCompile(`\s+`)
)

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Candidates returns what can be done on a page, in document order, and
// how many controls were left alone, by reason.
func Candidates(p *Page) ([]Candidate, map[string]int) {
	skipped := map[string]int{}
	n := len(p.Nodes)
	interactive := make([]bool, n)
	inert := make([]bool, n) // disabled, inert, or in a disabled fieldset
	hosts := make([]bool, n) // under a click listener's node: events delegated to it reach the node
	for i := range p.Nodes {
		nd := &p.Nodes[i]
		if par := nd.Parent; par >= 0 {
			inert[i] = inert[par]
			hosts[i] = hosts[par] || hasAny(p.Nodes[par].Listeners, clickTypes)
		}
		if nd.Type == 9 && hasAny(nd.Listeners, clickTypes) {
			hosts[i] = true
		}
		if nd.Type != 1 {
			continue
		}
		if _, ok := nd.Attrs["inert"]; ok {
			inert[i] = true
		}
		if nd.Tag == "fieldset" {
			if _, ok := nd.Attrs["disabled"]; ok {
				inert[i] = true
			}
		}
		if _, ok := nd.Attrs["disabled"]; ok && formControl(nd.Tag) {
			inert[i] = true
		}
		if strings.EqualFold(nd.Attrs["aria-disabled"], "true") {
			inert[i] = true
		}
		interactive[i] = isInteractive(p, i)
	}
	// Under a delegated listener, what the page styles as clickable is: the
	// outermost node with cursor:pointer (the style is inherited).
	pointer := make([]bool, n)
	for i := range p.Nodes {
		nd := &p.Nodes[i]
		if nd.Type != 1 || !hosts[i] || nd.Cursor != "pointer" || interactive[i] {
			continue
		}
		if par := nd.Parent; par >= 0 && p.Nodes[par].Cursor == "pointer" {
			continue
		}
		pointer[i] = true
	}
	// A node with a listener that holds other nodes explore will act on is
	// a container the events are delegated to: those are clicked, not it.
	// Only what is shown counts (a menu's hidden items do not make it a
	// container), and links do not (the frontier has them).
	inner := make([]int, n)         // how many nodes under each that explore acts on
	innerPointer := make([]bool, n) // whether any of them is one by its cursor alone
	for i := n - 1; i >= 0; i-- {
		nd := &p.Nodes[i]
		par := nd.Parent
		if par < 0 {
			continue
		}
		inner[par] += inner[i]
		innerPointer[par] = innerPointer[par] || innerPointer[i]
		if nd.Type == 1 && nd.Visible && !inert[i] && (interactive[i] || pointer[i]) && !(nd.Tag == "a" && realHref(nd.Attrs)) {
			inner[par]++
			innerPointer[par] = innerPointer[par] || pointer[i]
		}
	}

	var out []Candidate
	add := func(i int, a Action) {
		nd := &p.Nodes[i]
		c := Candidate{Node: i, Backend: nd.Backend, Frame: p.Docs[nd.Doc].Frame, Action: a, Tag: nd.Tag,
			Role: role(nd), Type: strings.ToLower(nd.Attrs["type"]), ID: nd.Attrs["id"], Label: p.label(i), Selector: p.selector(i)}
		if p.endsSession(i, c.Label) {
			skipped[SessionEnd]++
			return
		}
		out = append(out, c)
	}
	for i := range p.Nodes {
		nd := &p.Nodes[i]
		if nd.Type != 1 || inert[i] || !nd.Visible {
			continue
		}
		if !interactive[i] && !pointer[i] {
			continue
		}
		own := nd.Listeners
		// A container of things explore acts on: those, not it; unless it
		// has a click handler of its own and holds a few controls (a card
		// with a button in it). One that page styles its children as
		// clickable in is where their events are delegated to.
		if inner[i] > 0 && !semantic(nd) {
			ownClick := hasAny(own, clickTypes) || nd.Attrs["onclick"] != ""
			if !ownClick || inner[i] >= 3 || innerPointer[i] || listTags[nd.Tag] || listRoles[role(nd)] {
				continue
			}
		}
		switch {
		case nd.Tag == "input":
			t := strings.ToLower(nd.Attrs["type"])
			switch {
			case t == "checkbox" || t == "radio":
				add(i, Check)
			case t == "file":
				add(i, Upload)
			case t == "submit" || t == "image":
				add(i, Submit)
			case t == "button" || t == "reset":
				if t == "button" {
					add(i, Click)
				}
			case textTypes[t]:
				if editable(nd) && nd.Value == "" {
					add(i, Type)
				}
				if hasAny(own, keyTypes) || nd.Attrs["onkeydown"] != "" || nd.Attrs["onkeyup"] != "" || nd.Attrs["onkeypress"] != "" {
					add(i, Key)
				}
			}
		case nd.Tag == "textarea":
			if editable(nd) && nd.Value == "" {
				add(i, Type)
			}
		case nd.Tag == "select":
			add(i, Select)
		case nd.Tag == "button" && p.submits(i):
			add(i, Submit)
		case nd.Tag == "a" && realHref(nd.Attrs):
			// A link: the frontier has its URL. Only listeners of its own (a
			// prefetch on hover, a click that opens a dialog) are worth an
			// action; where it goes, the guard keeps the page from.
			if hasAny(own, hoverTypes) || nd.Attrs["onmouseover"] != "" || nd.Attrs["onmouseenter"] != "" {
				add(i, Hover)
			}
			if hasAny(own, clickTypes) || nd.Attrs["onclick"] != "" {
				add(i, Click)
			}
			continue
		case contentEditable(nd):
			if strings.TrimSpace(p.text(i)) == "" {
				add(i, Type)
			}
		default:
			// A hover first: a menu opens, a prefetch goes, before the click.
			if hasAny(own, hoverTypes) || nd.Attrs["onmouseover"] != "" || nd.Attrs["onmouseenter"] != "" {
				add(i, Hover)
			}
			// A click only where one is heard: not on what only takes a
			// double click or a right click.
			_, tab := nd.Attrs["tabindex"]
			if nd.Clickable || semantic(nd) || pointer[i] || hasAny(own, clickTypes) || nd.Attrs["onclick"] != "" ||
				nd.Attrs["onmousedown"] != "" || nd.Attrs["onmouseup"] != "" || tab {
				add(i, Click)
			}
		}
		if nd.Tag != "input" && nd.Tag != "textarea" && nd.Tag != "select" {
			if has(own, "dblclick") || nd.Attrs["ondblclick"] != "" {
				add(i, DblClick)
			}
			if has(own, "contextmenu") || nd.Attrs["oncontextmenu"] != "" {
				add(i, ContextMenu)
			}
		}
	}
	// A form with no submit button is sent with Enter in a field.
	for i := range p.Nodes {
		if p.Nodes[i].Tag != "form" || inert[i] {
			continue
		}
		hasSubmit, field := false, -1
		for _, c := range out {
			if !p.Contains(i, c.Node) {
				continue
			}
			if c.Action == Submit {
				hasSubmit = true
			}
			if field < 0 && (c.Action == Type || (c.Tag == "input" && textTypes[c.Type])) {
				field = c.Node
			}
		}
		if !hasSubmit && field >= 0 && !hasCandidate(out, field, Key) {
			add(field, Key)
		}
	}
	p.sign(out)
	return out, skipped
}

var (
	// A list's listener is its items' (delegation), never a card's own.
	listTags  = set("ul", "ol", "dl", "table", "tbody", "thead", "nav", "menu", "form", "main", "section", "header", "footer", "aside")
	listRoles = set("list", "listbox", "grid", "table", "menu", "menubar", "tablist", "toolbar", "tree", "navigation", "radiogroup")
	rowTags   = set("tr", "li", "option", "article", "dt", "dd")
	rowRoles  = set("row", "listitem", "option", "gridcell", "treeitem", "article")
)

// sign gives each candidate its signature. Rows of a list or a table do
// the same thing whatever their text says ("View INV-001", a clickable row
// named after a customer): a candidate that is, or sits in, one of three or
// more siblings alike is signed without its label. A toolbar's buttons,
// alike but for their names, and a menu whose items hold nothing but their
// name, keep theirs.
func (p *Page) sign(cs []Candidate) {
	type unit struct {
		key  string
		node int // the repeated node: a row
	}
	units := make([]unit, len(cs))
	rows := map[string]map[int]bool{} // key -> the rows holding such a candidate
	for k, c := range cs {
		path := ""
		for u, depth := c.Node, 0; depth < 5; depth++ {
			par := p.Nodes[u].Parent
			if par < 0 || p.Nodes[par].Type != 1 {
				break
			}
			// A row is a list item, a table row, or a repeated component
			// (it has a class); plain sections alike are no list.
			un := &p.Nodes[u]
			rowLike := rowTags[un.Tag] || rowRoles[role(un)] || firstClass(un.Attrs) != ""
			if alike := p.alike(par, u); alike >= 3 && rowLike {
				self := u == c.Node
				if self && !rowTags[p.Nodes[u].Tag] && !rowRoles[role(&p.Nodes[u])] && alike < 12 {
					break
				}
				if !self && clean(p.text(u)) == c.Label && alike < 12 {
					break // a menu item: the row is the control
				}
				units[k] = unit{key: fmt.Sprintf("%d>%s|%s", par, path, c.Action), node: u}
				if rows[units[k].key] == nil {
					rows[units[k].key] = map[int]bool{}
				}
				rows[units[k].key][u] = true
				break
			}
			path = p.Nodes[u].Tag + "/" + path
			u = par
		}
	}
	for k := range cs {
		label := cs[k].Label
		// Alike in two rows at least: two cards in one container are not.
		if units[k].key != "" && len(rows[units[k].key]) >= 2 {
			label = "*"
		}
		cs[k].Sig = p.signature(cs[k].Node, cs[k], label)
		nd := &p.Nodes[cs[k].Node]
		cs[k].Raw = strings.Join([]string{string(cs[k].Action), cs[k].Selector, nd.Attrs["name"], cs[k].Label, p.Docs[nd.Doc].Frame}, "|")
	}
}

// alike counts the element children of par with the tag and first class of
// child.
func (p *Page) alike(par, child int) int {
	tag, cls := p.Nodes[child].Tag, firstClass(p.Nodes[child].Attrs)
	n := 0
	for _, c := range p.Nodes[par].Children {
		if p.Nodes[c].Type == 1 && p.Nodes[c].Tag == tag && firstClass(p.Nodes[c].Attrs) == cls {
			n++
		}
	}
	return n
}

func firstClass(a map[string]string) string {
	if f := strings.Fields(a["class"]); len(f) > 0 {
		return f[0]
	}
	return ""
}

func hasCandidate(cs []Candidate, node int, a Action) bool {
	for _, c := range cs {
		if c.Node == node && c.Action == a {
			return true
		}
	}
	return false
}

func isInteractive(p *Page, i int) bool {
	nd := &p.Nodes[i]
	if nd.Clickable || semantic(nd) || contentEditable(nd) {
		return true
	}
	if hasAny(nd.Listeners, clickTypes) || hasAny(nd.Listeners, hoverTypes) || hasAny(nd.Listeners, keyTypes) ||
		has(nd.Listeners, "dblclick") || has(nd.Listeners, "contextmenu") {
		return true
	}
	for a := range nd.Attrs {
		if inlineHandlers[a] {
			return true
		}
	}
	if t, err := strconv.Atoi(strings.TrimSpace(nd.Attrs["tabindex"])); err == nil && t >= 0 && nd.Tag != "html" && nd.Tag != "body" {
		return true
	}
	return false
}

// semantic reports whether an element is interactive by what it is: a
// control, a summary, a link that is a button, or an ARIA widget role.
func semantic(nd *Node) bool {
	switch nd.Tag {
	case "button", "select", "textarea", "summary":
		return true
	case "input":
		return !strings.EqualFold(nd.Attrs["type"], "hidden")
	case "a":
		if _, ok := nd.Attrs["href"]; ok && !realHref(nd.Attrs) {
			return true
		}
	}
	return roles[strings.ToLower(strings.TrimSpace(nd.Attrs["role"]))]
}

func formControl(tag string) bool {
	switch tag {
	case "button", "input", "select", "textarea", "optgroup", "option", "fieldset":
		return true
	}
	return false
}

func editable(nd *Node) bool {
	_, ro := nd.Attrs["readonly"]
	return !ro
}

func contentEditable(nd *Node) bool {
	v, ok := nd.Attrs["contenteditable"]
	return ok && !strings.EqualFold(v, "false")
}

// realHref reports whether a link goes somewhere: not "#…", not a
// javascript: URL.
func realHref(a map[string]string) bool {
	h, ok := a["href"]
	if !ok {
		return false
	}
	h = strings.TrimSpace(h)
	return h != "" && !strings.HasPrefix(h, "#") && !strings.HasPrefix(strings.ToLower(h), "javascript:")
}

// submits reports whether a button submits its form.
func (p *Page) submits(i int) bool {
	t := strings.ToLower(strings.TrimSpace(p.Nodes[i].Attrs["type"]))
	if t != "" && t != "submit" {
		return false
	}
	if p.Nodes[i].Attrs["form"] != "" {
		return true
	}
	for a := p.Nodes[i].Parent; a >= 0; a = p.Nodes[a].Parent {
		if p.Nodes[a].Tag == "form" {
			return true
		}
		if p.Nodes[a].Type != 1 {
			break // the edge of a shadow root or a frame
		}
	}
	return false
}

func role(nd *Node) string {
	if r := strings.ToLower(strings.TrimSpace(nd.Attrs["role"])); r != "" {
		return r
	}
	switch nd.Tag {
	case "a":
		return "link"
	case "button", "summary":
		return "button"
	case "select":
		return "combobox"
	case "textarea":
		return "textbox"
	case "input":
		switch strings.ToLower(nd.Attrs["type"]) {
		case "button", "submit", "reset", "image":
			return "button"
		case "checkbox":
			return "checkbox"
		case "radio":
			return "radio"
		case "file":
			return "file"
		}
		return "textbox"
	}
	return ""
}

// label is the name a person sees: aria-label, aria-labelledby, the text,
// a button's value, the field's <label>, its placeholder, title or name.
func (p *Page) label(i int) string {
	nd := &p.Nodes[i]
	if v := nd.Attrs["aria-label"]; strings.TrimSpace(v) != "" {
		return clean(v)
	}
	if by := nd.Attrs["aria-labelledby"]; by != "" {
		var parts []string
		for _, id := range strings.Fields(by) {
			if j, ok := p.byID[nd.Doc][id]; ok {
				parts = append(parts, p.text(j))
			}
		}
		if s := clean(strings.Join(parts, " ")); s != "" {
			return s
		}
	}
	switch nd.Tag {
	case "input", "textarea", "select":
		t := strings.ToLower(nd.Attrs["type"])
		if nd.Tag == "input" && (t == "button" || t == "submit" || t == "reset") {
			if v := nd.Attrs["value"]; v != "" {
				return clean(v)
			}
		}
		if s := p.fieldLabel(i); s != "" {
			return s
		}
		for _, a := range []string{"placeholder", "title", "alt", "name"} {
			if v := nd.Attrs[a]; v != "" {
				return clean(v)
			}
		}
		return ""
	}
	if s := clean(p.text(i)); s != "" {
		return s
	}
	for _, a := range []string{"title", "alt", "name", "value"} {
		if v := nd.Attrs[a]; v != "" {
			return clean(v)
		}
	}
	// An icon button: the alt of its image, the title of its svg.
	var alt string
	p.walk(i, func(j int) bool {
		if c := &p.Nodes[j]; c.Type == 1 && (c.Attrs["alt"] != "" || c.Attrs["aria-label"] != "") {
			alt = c.Attrs["aria-label"]
			if alt == "" {
				alt = c.Attrs["alt"]
			}
			return false
		}
		return true
	})
	return clean(alt)
}

// fieldLabel is the text of a field's <label>: one that names its id, or
// one around it.
func (p *Page) fieldLabel(i int) string {
	nd := &p.Nodes[i]
	if id := nd.Attrs["id"]; id != "" {
		for j := range p.Nodes {
			if l := &p.Nodes[j]; l.Doc == nd.Doc && l.Tag == "label" && l.Attrs["for"] == id {
				return clean(p.text(j))
			}
		}
	}
	for a := nd.Parent; a >= 0 && p.Nodes[a].Type == 1; a = p.Nodes[a].Parent {
		if p.Nodes[a].Tag == "label" {
			return clean(p.text(a))
		}
	}
	return ""
}

// text is the text under a node that is rendered, without scripts,
// styles, or the text of fields.
func (p *Page) text(i int) string {
	var b strings.Builder
	p.walk(i, func(j int) bool {
		c := &p.Nodes[j]
		switch {
		case c.Type == 3:
			b.WriteString(c.Text)
			b.WriteByte(' ')
		case c.Tag == "script" || c.Tag == "style" || c.Tag == "noscript" || c.Tag == "template" || c.Tag == "select" || c.Tag == "textarea":
			return false
		case c.Shadow || c.Type == 9:
			return false // another tree: its text is not this node's
		case c.Type == 1 && j != i && c.Box == nil:
			return false // not rendered (hidden, a closed details): not what a person reads
		}
		return b.Len() < 400
	})
	return b.String()
}

// walk visits a node and its descendants in document order while f
// returns true for the node.
func (p *Page) walk(i int, f func(int) bool) {
	if !f(i) {
		return
	}
	for _, c := range p.Nodes[i].Children {
		p.walk(c, f)
	}
}

func clean(s string) string {
	s = strings.TrimSpace(spaceRe.ReplaceAllString(s, " "))
	if r := []rune(s); len(r) > 60 {
		s = string(r[:60])
	}
	return s
}

// selector is a short CSS path, for people reading the flows.
func (p *Page) selector(i int) string {
	var parts []string
	for n := i; n >= 0 && p.Nodes[n].Type == 1 && len(parts) < 3; n = p.Nodes[n].Parent {
		nd := &p.Nodes[n]
		if id := nd.Attrs["id"]; id != "" {
			parts = append([]string{nd.Tag + "#" + id}, parts...)
			break
		}
		s := nd.Tag
		if cls := strings.Fields(nd.Attrs["class"]); len(cls) > 0 {
			s += "." + cls[0]
		}
		parts = append([]string{s}, parts...)
	}
	return strings.Join(parts, " > ")
}

// endsSession reports whether a control names a logout.
func (p *Page) endsSession(i int, label string) bool {
	if label != "" && (sessionEndRe.MatchString(label) || camelEndRe.MatchString(label)) {
		return true
	}
	// Its own attributes, and those of what it holds: an icon button
	// (<i class="fa-sign-out">, <svg><use href="#logout">) says it there.
	found, seen := false, 0
	p.walk(i, func(j int) bool {
		if seen++; found || seen > 30 {
			return false
		}
		a := p.Nodes[j].Attrs
		for _, s := range []string{a["id"], a["name"], a["class"], a["href"], a["xlink:href"], a["formaction"], a["title"],
			a["aria-label"], a["data-action"], a["data-testid"], a["data-test"], a["data-cy"]} {
			if s != "" && (sessionEndRe.MatchString(s) || camelEndRe.MatchString(s)) {
				found = true
				return false
			}
		}
		return true
	})
	if found {
		return true
	}
	if p.Nodes[i].Tag == "button" || p.Nodes[i].Tag == "input" {
		for f := p.Nodes[i].Parent; f >= 0 && p.Nodes[f].Type == 1; f = p.Nodes[f].Parent {
			if p.Nodes[f].Tag == "form" {
				if act := p.Nodes[f].Attrs["action"]; act != "" && sessionEndRe.MatchString(act) {
					return true
				}
				break
			}
		}
	}
	return false
}

// signature is what one element shares with the elements that do the same
// thing: rows of a list, a button on every page. Digits are wildcards, so
// "Show 10 more" and "Show 20 more", or row-41 and row-42, are one.
func (p *Page) signature(i int, c Candidate, label string) string {
	nd := &p.Nodes[i]
	return strings.Join([]string{nd.Tag, c.Role, c.Type, norm(nd.Attrs["id"]), norm(firstClass(nd.Attrs)), norm(nd.Attrs["name"]),
		norm(strings.ToLower(label)), p.context(i), string(c.Action)}, "|")
}

// context is where an element is: its form (the action, or the names of
// its fields: an app's forms post from script), or else the id of its
// nearest ancestor that has one. Not the page: an app shows the same
// controls on all its routes, and each is used once a run. Frames add
// their document's path.
func (p *Page) context(i int) string {
	ctx := ""
	for a := p.Nodes[i].Parent; a >= 0 && p.Nodes[a].Type == 1; a = p.Nodes[a].Parent {
		at := p.Nodes[a].Attrs
		if p.Nodes[a].Tag == "form" {
			if act := at["action"]; act != "" {
				ctx = "form:" + norm(pathOf(act))
			} else {
				// An app's form posts from script: what it holds names it.
				ctx = "form:" + p.fieldNames(a)
			}
			break
		}
		if id := at["id"]; id != "" {
			ctx = "#" + norm(id)
			break
		}
	}
	doc := p.Docs[p.Nodes[i].Doc]
	if p.Nodes[i].Doc > 0 {
		ctx += "@" + norm(pathOf(doc.URL))
	}
	return ctx
}

// fieldNames lists the names of a form's fields, sorted.
func (p *Page) fieldNames(form int) string {
	var names []string
	p.walk(form, func(j int) bool {
		if c := &p.Nodes[j]; c.Type == 1 && (c.Tag == "input" || c.Tag == "select" || c.Tag == "textarea") {
			if n := c.Attrs["name"]; n != "" && !slices.Contains(names, n) {
				names = append(names, norm(n))
			}
		}
		return len(names) < 12
	})
	slices.Sort(names)
	return strings.Join(names, ",")
}

func pathOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Path
	}
	return raw
}

func norm(s string) string { return digitsRe.ReplaceAllString(s, "#") }

func has(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func hasAny(xs []string, m map[string]bool) bool {
	for _, x := range xs {
		if m[x] {
			return true
		}
	}
	return false
}
