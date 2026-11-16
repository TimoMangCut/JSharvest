package engine

import "github.com/TimoMangCut/JSharvest/internal/marker"

// exploreLib runs in explore's isolated world of each frame, out of the
// page's reach, and gives the Go side what it needs of the DOM: a value a
// field accepts, a form made valid, the page's clock, a scroll step. It
// sets values the page way (the prototype's setter, then input and change
// events), so that frameworks that track a field's value see the change.
// SAMPLES is replaced with the sample values, by input type.
const exploreLib = `(() => {
  if (globalThis.__jshx) return;
  const S = SAMPLES;
  const fire = (el, ...types) => { for (const t of types) el.dispatchEvent(new Event(t, {bubbles: true})); };
  const setValue = (el, v) => {
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype
      : el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value").set.call(el, v);
  };
  const compile = (src) => {
    for (const flags of ["v", "u", ""]) {
      try { return new RegExp("^(?:" + src + ")$", flags); } catch (_) {}
    }
    return null;
  };
  // gen makes a string that a pattern attribute matches: the first branch
  // of each alternation, the least of each quantifier (one at least for +),
  // the first character a class takes. It returns null when it cannot.
  const gen = (src) => {
    let i = 0;
    const printable = "aA1zZ9x_-. @/" + Array.from({length: 95}, (_, k) => String.fromCharCode(32 + k)).join("");
    const cls = () => {
      const start = i; // at "["
      let depth = 0;
      for (i++; i < src.length; i++) {
        if (src[i] === "\\") { i++; continue; }
        if (src[i] === "[") depth++;
        if (src[i] === "]") { if (depth === 0) break; depth--; }
      }
      const body = src.slice(start, ++i);
      const re = compile(body);
      if (!re) return null;
      for (const ch of printable) if (re.test(ch)) return ch;
      return null;
    };
    const atom = () => {
      const c = src[i];
      if (c === "(") {
        i++;
        let look = false;
        if (src[i] === "?") {
          if (src[i + 1] === ":") i += 2;
          else if (src[i + 1] === "<" && src[i + 2] !== "=" && src[i + 2] !== "!") { i = src.indexOf(">", i) + 1; }
          else { look = true; i += src[i + 1] === "<" ? 3 : 2; }
        }
        const r = alt();
        i++; // ")"
        return look ? "" : r;
      }
      if (c === "[") return cls();
      if (c === "\\") {
        const e = src[i + 1];
        i += 2;
        if (e === "d") return "1";
        if (e === "w") return "a";
        if (e === "s") return " ";
        if (e === "D" || e === "S" || e === "W") return e === "W" ? "-" : "a";
        if (e === "b" || e === "B" || /[0-9]/.test(e)) return "";
        if (e === "u" && src[i] === "{") { const j = src.indexOf("}", i); const cp = parseInt(src.slice(i + 1, j), 16); i = j + 1; return String.fromCodePoint(cp); }
        if (e === "u" || e === "x") { const n = e === "u" ? 4 : 2; const cp = parseInt(src.slice(i, i + n), 16); i += n; return String.fromCharCode(cp); }
        return e;
      }
      i++;
      if (c === "." ) return "a";
      if (c === "^" || c === "$") return "";
      return c;
    };
    const seq = () => {
      let out = "";
      while (i < src.length && src[i] !== "|" && src[i] !== ")") {
        const a = atom();
        if (a === null) return null;
        let n = 1;
        const q = src[i];
        if (q === "*" || q === "?") { n = 0; i++; }
        else if (q === "+") { n = 1; i++; }
        else if (q === "{") {
          const j = src.indexOf("}", i);
          const m = /^\{(\d+)(,(\d*))?\}$/.exec(src.slice(i, j + 1));
          if (m) { n = Number(m[1]); i = j + 1; }
        }
        if (src[i] === "?" && (q === "*" || q === "+" || q === "?" || q === "{")) i++; // lazy
        out += a.repeat(n);
      }
      return out;
    };
    const alt = () => {
      const first = seq();
      while (src[i] === "|") { i++; seq(); }
      return first;
    };
    try {
      const out = alt();
      const re = compile(src);
      return out !== null && re && re.test(out) ? out : null;
    } catch (_) { return null; }
  };
  const hint = (el) => [el.name, el.id, el.placeholder, el.getAttribute("autocomplete"), el.getAttribute("aria-label"), el.title]
    .filter(Boolean).join(" ").toLowerCase();
  const choose = (el) => {
    if (!(el instanceof HTMLInputElement) && !(el instanceof HTMLTextAreaElement)) return S.text;
    const t = (el.type || "text").toLowerCase(), h = hint(el);
    let v;
    if (el instanceof HTMLTextAreaElement) v = S.text;
    else if (t === "number" || t === "range") {
      const min = parseFloat(el.min), max = parseFloat(el.max);
      v = String(!isNaN(min) ? min : !isNaN(max) && max < 1 ? max : 1);
    } else if (t === "password") v = S.password;
    else if (S[t] !== undefined && t !== "text" && t !== "search") v = el.min && /date|month|week|time/.test(t) ? el.min : S[t];
    else if (/e-?mail/.test(h)) v = S.email;
    else if (/phone|tel|mobile/.test(h)) v = S.tel;
    else if (/zip|postal|postcode/.test(h)) v = "10001";
    else if (/url|website|homepage/.test(h)) v = S.url;
    else if (/\byear\b/.test(h)) v = "2026";
    else if (/date|birth/.test(h)) v = S.date;
    else if (/\b(age|qty|quantity|amount|count|number|price)\b/.test(h)) v = "1";
    else if (/name/.test(h)) v = "Test";
    else v = S.text;
    if (el.pattern) {
      const re = compile(el.pattern);
      if (re && !re.test(v)) { const g = gen(el.pattern); if (g !== null) v = g; }
    } else {
      while (el.minLength > 0 && v.length < el.minLength) v += "x";
    }
    if (el.maxLength > 0 && v.length > el.maxLength) v = v.slice(0, el.maxLength);
    return v;
  };
  // fix gives a field a value it accepts, as a person would have.
  const fix = (el) => {
    if (el instanceof HTMLInputElement && el.type === "checkbox") {
      if (!el.checked) { el.checked = true; fire(el, "input", "change"); }
      return;
    }
    if (el instanceof HTMLInputElement && el.type === "radio") {
      const group = el.form && el.name ? [...el.form.elements].filter((e) => e.type === "radio" && e.name === el.name) : [el];
      if (!group.some((r) => r.checked)) { group[0].checked = true; fire(group[0], "input", "change"); }
      return;
    }
    if (el instanceof HTMLSelectElement) {
      const o = [...el.options].find((o) => !o.disabled && o.value !== "");
      if (o) { setValue(el, o.value); fire(el, "input", "change"); }
      return;
    }
    if (el instanceof HTMLInputElement && el.type === "file") return;
    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) { setValue(el, choose(el)); fire(el, "input", "change"); }
  };
  globalThis.__jshx = {
    choose,
    fix,
    value: (el) => "value" in el ? String(el.value) : (el.textContent || ""),
    valid: (el) => !el.willValidate || el.validity.valid,
    // Before a submit button is clicked: fix what the browser would refuse.
    prepare: (btn) => {
      const f = btn.form || (btn.closest && btn.closest("form"));
      if (!f) return true;
      // What the browser refuses, and what is empty: a form checked by
      // script (novalidate) says nothing to the constraint API.
      const typed = /^(|text|search|email|url|tel|password|number)$/;
      for (const c of f.elements) {
        if (c.willValidate && !c.validity.valid) fix(c);
        else if (c.willValidate && !c.readOnly && c.value === "" && (c instanceof HTMLTextAreaElement || (c instanceof HTMLInputElement && typed.test(c.type)))) fix(c);
      }
      return f.checkValidity();
    },
    // After ArrowDown: if the choice did not change, make it change.
    selectNext: (el, before) => {
      if (el.value !== before) return el.value;
      const next = [...el.options].find((o) => !o.disabled && o.value !== before && o.value !== "");
      if (next) { setValue(el, next.value); fire(el, "input", "change"); }
      return el.value;
    },
    click: (el) => { el.click(); return true; },
    center: (el) => { el.scrollIntoView({block: "center", inline: "center"}); return true; },
    accept: (el) => el.accept || "",
    clock: () => performance.timeOrigin + ":" + performance.now(),
    href: () => location.href,
    // One step of scrolling: the page to its end, and the first twenty
    // boxes that scroll on their own (a feed in a panel). It returns what
    // changes when more content came.
    scroll: () => {
      const doc = document.scrollingElement || document.documentElement;
      window.scrollTo(0, doc.scrollHeight);
      let sum = doc.scrollHeight, boxes = 0, looked = 0;
      for (const el of document.querySelectorAll("body *")) {
        if (boxes >= 20 || ++looked > 5000) break;
        if (el.scrollHeight > el.clientHeight + 20 && el.clientHeight > 40) {
          const oy = getComputedStyle(el).overflowY;
          if (oy === "auto" || oy === "scroll" || oy === "overlay") { el.scrollTop = el.scrollHeight; sum += el.scrollHeight; boxes++; }
        }
      }
      return sum;
    },
    top: () => { window.scrollTo(0, 0); return true; },
  };
})()
//# sourceURL=` + marker.Internal
