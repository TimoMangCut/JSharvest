package capture

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/debugger"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/marker"
)

const (
	actionWorld   = "jsharvest-actions"
	actionBinding = "__jshAction"
	asyncDepth    = 32
)

// actionTypes are the events the reporter reports, and the tagger wraps.
const actionTypes = `["click","dblclick","pointerup","mouseup","keydown","input","change","submit","popstate","hashchange"]`

// quietTypes are wrapped too, and not reported: a person's pointer crosses
// elements all the time, and an action for each would bury the clicks. A
// timer a handler of theirs sets is then known to be no background work
// ("jsh:none"), and its request is placed by time, under the action
// (explore's hover or scroll, a person's last gesture) going on.
const quietTypes = `["mouseover","mouseenter","mouseout","mouseleave","pointerover","pointerenter","pointerdown","mousedown","keyup","keypress","contextmenu","focus","focusin","blur","scroll","wheel","touchstart","touchend"]`

// tagScript runs in the page's own world, before its scripts. It wraps
// event handlers so that each runs in a console.createTask task named after
// the event; Chrome then names that task in the async stack of every
// request the handler starts, however late (setTimeout, await, promises).
// It changes nothing a handler can see but the function identity, which
// removeEventListener and the on* getters hide.
const tagScript = `(() => {
  const mark = Symbol.for("` + marker.TaggerKey + `");
  if (window[mark] || !console.createTask) return;
  window[mark] = true;
  const types = new Set([...` + actionTypes + `, ...` + quietTypes + `]);
  const origin = performance.timeOrigin;
  const wrapped = new WeakMap(), original = new WeakMap();
  // The action whose code runs now, while a handler runs synchronously or
  // a timer it set fires.
  let current = null;
  // The browser's own createTask, taken before any page script runs: the
  // task names never pass through a function the page could replace.
  const createTask = console.createTask.bind(console);
  const within = (name, f) => {
    const prev = current;
    current = name;
    try { return createTask(name).run(f); } finally { current = prev; }
  };
  const wrap = (fn) => {
    if (typeof fn !== "function" && !(fn && typeof fn.handleEvent === "function")) return fn;
    let w = wrapped.get(fn);
    if (!w) {
      w = function (ev) {
        const call = () => typeof fn === "function" ? fn.apply(this, arguments) : fn.handleEvent(ev);
        if (!ev || typeof ev.timeStamp !== "number") return call();
        return within("` + marker.TaskPrefix + `" + origin + ":" + ev.timeStamp + ":" + ev.type, call);
      };
      wrapped.set(fn, w);
      original.set(w, fn);
    }
    return w;
  };
  // A timer runs its callback in a fresh task named after the action that
  // set it, or "none" for one set outside any action (the page's start, a
  // background poll), and after the timer. V8 keeps a limited number of
  // async stacks and drops the oldest on a busy page, which would cut the
  // chain from a late request back to its cause; this link is made when
  // the timer fires, so it is always there. The suffix tells a one-off
  // delay from a repeating poll.
  for (const name of ["setTimeout", "setInterval"]) {
    const timer = window[name];
    window[name] = function (fn, ...rest) {
      if (typeof fn !== "function") return timer.call(this, fn, ...rest);
      const cause = current ? current.replace(/:(setTimeout|setInterval)$/, "") : "` + marker.TaskPrefix + `none:" + origin;
      const args = rest.slice(1);
      // An interval's first firing is a delay (RxJS makes one-shot delays
      // with setInterval); only from the second does it repeat.
      let fired = 0;
      return timer.call(this, function () {
        const kind = name === "setInterval" && fired++ > 0 ? "setInterval" : "setTimeout";
        return within(cause + ":" + kind, () => fn.apply(this, args));
      }, rest[0]);
    };
  }
  const proto = EventTarget.prototype, add = proto.addEventListener, remove = proto.removeEventListener;
  // A listener the page added before the tagger (watch on a loaded page)
  // is still there unwrapped: take it off before adding the wrapper, and
  // remove both, so that no handler runs twice or outlives its removal.
  proto.addEventListener = function (type, fn, opts) {
    if (!types.has(type)) return add.call(this, type, fn, opts);
    const w = wrap(fn);
    if (w !== fn) remove.call(this, type, fn, opts);
    return add.call(this, type, w, opts);
  };
  proto.removeEventListener = function (type, fn, opts) {
    const w = types.has(type) && wrapped.get(fn);
    if (w) remove.call(this, type, w, opts);
    return remove.call(this, type, fn, opts);
  };
  // on<type> setters live on HTMLElement, SVGElement and Document's
  // prototypes, and on the window object itself.
  const owners = [HTMLElement.prototype, SVGElement.prototype, Document.prototype, window];
  if (typeof MathMLElement === "function") owners.push(MathMLElement.prototype);
  for (const obj of owners) {
    for (const type of types) {
      const d = Object.getOwnPropertyDescriptor(obj, "on" + type);
      if (!d || !d.set || !d.configurable) continue;
      Object.defineProperty(obj, "on" + type, {
        configurable: true, enumerable: d.enumerable,
        get() { const w = d.get.call(this); return (w && original.get(w)) || w; },
        // An on<type> property takes functions only; anything else is null.
        set(fn) { d.set.call(this, typeof fn === "function" ? wrap(fn) : fn); },
      });
    }
  }
})()
//# sourceURL=` + marker.Tagger

// reportScript runs in an isolated world, out of the page's reach, and
// reports every event of actionTypes through a binding that exists only in
// that world, so the page cannot forge actions.
const reportScript = `(() => {
  if (window.__jshReporter) return;
  window.__jshReporter = true;
  // The binding is looked up when used: Chrome may add it to this world
  // after the script has run.
  const send = (msg) => globalThis.` + actionBinding + `(msg);
  const origin = performance.timeOrigin;
  const interactive = "button,a,[role=button],[role=link],[role=tab],[role=menuitem],input,select,textarea,label,summary,[onclick]";
  const text = (s) => (s || "").replace(/\s+/g, " ").trim().slice(0, 60);
  const role = (el) => el.getAttribute("role") || ({A: "link", BUTTON: "button", SELECT: "combobox", TEXTAREA: "textbox"}[el.tagName]) ||
    (el.tagName === "INPUT" ? ({button: "button", submit: "button", checkbox: "checkbox", radio: "radio"}[el.type] || "textbox") : "");
  // Form controls named "action", "id" or "name" shadow those properties
  // on a form (form.action is then the input), and an SVG link's href is an
  // object: read attributes, and keep strings only.
  const attr = (el, name) => { const v = el.getAttribute(name); return typeof v === "string" ? v : ""; };
  const str = (v) => typeof v === "string" ? v : "";
  const formAction = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, "action").get;
  const label = (el) => {
    const by = attr(el, "aria-labelledby");
    const named = by && by.split(/\s+/).map((id) => document.getElementById(id)).filter(Boolean).map((n) => n.textContent).join(" ");
    // Never what the user typed: no values of text fields, no editable text.
    const own = el.isContentEditable || ["INPUT", "TEXTAREA", "SELECT", "BODY", "HTML"].includes(el.tagName) ? "" : (el.textContent || "").slice(0, 200);
    const value = el.tagName === "INPUT" && ["button", "submit", "reset"].includes(attr(el, "type")) ? attr(el, "value") : "";
    return text(attr(el, "aria-label") || named || own || value || attr(el, "placeholder") || attr(el, "title") || attr(el, "alt") || attr(el, "name"));
  };
  const selector = (el) => {
    const parts = [];
    for (let n = el; n && n.nodeType === 1 && parts.length < 3; n = n.parentElement) {
      if (n.id) { parts.unshift(n.tagName.toLowerCase() + "#" + n.id); break; }
      const cls = n.classList && n.classList[0];
      parts.unshift(n.tagName.toLowerCase() + (cls ? "." + cls : ""));
    }
    return parts.join(" > ");
  };
  const describe = (raw) => {
    if (!(raw instanceof Element)) return null;
    const el = raw.closest(interactive) || raw;
    const form = el.tagName === "FORM" ? el : el.closest("form");
    return {tag: el.tagName.toLowerCase(), id: attr(el, "id"), name: attr(el, "name"), type: attr(el, "type"),
      role: role(el), label: label(el), selector: selector(el), href: el.tagName === "A" ? str(el.href) : "",
      action: form instanceof HTMLFormElement ? str(formAction.call(form)) : ""};
  };
  // Only the events that name an action carry its element; the others
  // (pointerup, keydown, input…) only join it, and cost nothing to read.
  const described = new Set(["click", "dblclick", "submit", "change"]);
  const on = (e) => {
    try {
      const path = e.composedPath ? e.composedPath() : [];
      send(JSON.stringify({tag: origin + ":" + e.timeStamp + ":" + e.type, type: e.type, wall: Date.now(), trusted: e.isTrusted,
        top: window === window.top, url: location.href, element: described.has(e.type) ? describe(path[0] || e.target) : null}));
    } catch (_) {}
  };
  for (const t of ` + actionTypes + `) window.addEventListener(t, on, {capture: true, passive: true});
})()
//# sourceURL=` + marker.Internal

// installActions sets a page or frame session up to report actions: async
// stacks deep enough to carry the tags, the binding, both scripts for the
// documents to come, and both for the document already there.
func (s *session) installActions() error {
	o := s.c.opts
	ctx, cancel := context.WithTimeout(s.ctx, o.CallTimeout)
	defer cancel()
	if o.NoDebugger {
		// The script capture did not turn it on; async stacks need it.
		if _, err := chromedp.Call(ctx, debugger.Enable, debugger.EnableParams{}); err != nil {
			return fmt.Errorf("debugger: %w", err)
		}
		// A debugger statement must not freeze the tab.
		if _, err := chromedp.Call(ctx, debugger.SetSkipAllPauses, debugger.SetSkipAllPausesParams{Skip: true}); err != nil {
			return fmt.Errorf("debugger: %w", err)
		}
	}
	if _, err := chromedp.Call(ctx, debugger.SetAsyncCallStackDepth, debugger.SetAsyncCallStackDepthParams{MaxDepth: asyncDepth}); err != nil {
		return fmt.Errorf("async stacks: %w", err)
	}
	if _, err := chromedp.Call(ctx, runtime.AddBinding, runtime.AddBindingParams{Name: actionBinding, ExecutionContextName: actionWorld}); err != nil {
		return fmt.Errorf("binding: %w", err)
	}
	go each(chromedp.Events(s.ctx, runtime.BindingCalled), func(ev *runtime.EventBindingCalled) {
		if ev.Name != actionBinding {
			return
		}
		// The page sends its wall time as milliseconds, and the element
		// apart: an element that does not decode never costs the event.
		var p struct {
			Tag     string          `json:"tag"`
			Type    string          `json:"type"`
			Wall    float64         `json:"wall"`
			Trusted bool            `json:"trusted"`
			Top     bool            `json:"top"`
			URL     string          `json:"url"`
			Element json.RawMessage `json:"element"`
		}
		if err := json.Unmarshal([]byte(ev.Payload), &p); err != nil {
			slog.Debug("action event", "err", err)
			return
		}
		e := flow.Event{Tag: p.Tag, Type: p.Type, Trusted: p.Trusted, Top: p.Top, URL: p.URL, Wall: time.UnixMilli(int64(p.Wall)).UTC()}
		var el flow.Element
		if len(p.Element) > 0 && string(p.Element) != "null" && json.Unmarshal(p.Element, &el) == nil {
			e.Element = &el
		}
		slog.Debug("action event", "type", e.Type, "trusted", e.Trusted, "tag", e.Tag)
		o.OnEvent(e)
	})
	var ids []page.ScriptIdentifier
	if !o.NoTagger {
		res, err := chromedp.Call(ctx, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{Source: tagScript})
		if err != nil {
			return fmt.Errorf("tagger: %w", err)
		}
		ids = append(ids, res.Identifier)
	}
	res, err := chromedp.Call(ctx, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{Source: reportScript, WorldName: actionWorld})
	if err != nil {
		return fmt.Errorf("reporter: %w", err)
	}
	ids = append(ids, res.Identifier)
	s.c.mu.Lock()
	s.c.hooks = append(s.c.hooks, hook{s: s, scripts: ids})
	s.c.mu.Unlock()

	slog.Debug("actions installed", "target", s.kind, "url", s.targetURL, "tagger", !o.NoTagger)

	// The document already loaded: an attached tab, or about:blank.
	if !o.NoTagger {
		if _, err := chromedp.Call(ctx, runtime.Evaluate, runtime.EvaluateParams{Expression: tagScript}); err != nil {
			slog.Debug("tagger in the current document", "err", err)
		}
	}
	world, err := chromedp.Call(ctx, page.CreateIsolatedWorld, page.CreateIsolatedWorldParams{FrameID: frameOf(s), WorldName: actionWorld})
	if err != nil {
		slog.Debug("reporter world in the current document", "err", err)
		return nil
	}
	if _, err := chromedp.Call(ctx, runtime.Evaluate, runtime.EvaluateParams{Expression: reportScript, ContextID: world.ExecutionContextID}); err != nil {
		slog.Debug("reporter in the current document", "err", err)
	}
	return nil
}

// hook is what installActions left in a session, so that Unhook can take
// it out again.
type hook struct {
	s       *session
	scripts []page.ScriptIdentifier
}

// Unhook removes the action scripts and the binding from the documents to
// come, so that a reload brings the page back as it was. The current
// document keeps them until it is reloaded.
func (c *Capture) Unhook() {
	c.mu.Lock()
	hooks := c.hooks
	c.hooks = nil
	c.mu.Unlock()
	for _, h := range hooks {
		ctx, cancel := context.WithTimeout(h.s.ctx, c.opts.CallTimeout)
		for _, id := range h.scripts {
			chromedp.Call(ctx, page.RemoveScriptToEvaluateOnNewDocument, page.RemoveScriptToEvaluateOnNewDocumentParams{Identifier: id})
		}
		chromedp.Call(ctx, runtime.RemoveBinding, runtime.RemoveBindingParams{Name: actionBinding})
		cancel()
	}
}

// frameOf is the frame of a session's document: a page's or a cross-site
// frame's main frame has the id of its target.
func frameOf(s *session) cdp.FrameID { return cdp.FrameID(s.id) }

func isActionTarget(kind string) bool { return kind == "page" || kind == "iframe" }
