// JSHMARK:explore:app
const $ = (s) => document.querySelector(s);
const get = (p) => fetch(p);
const post = (p, body) => fetch(p, { method: 'POST', body });

// 5. The route view: what /x/route shows, in place of the page.
function renderRoute() {
  $('#main').innerHTML = '<h2>Route</h2><button id="route-only">Route action</button>';
  $('#route-only').addEventListener('click', () => get('/api/x/route-only'));
}
// The two URLs below are built, not written: only acting finds them.
const at = (...p) => '/' + p.join('/');
if (location.pathname === at('x', 'route')) renderRoute();

// 1. Delegated to the root.
$('#root') && $('#root').addEventListener('click', (e) => {
  const card = e.target.closest('[data-act]');
  if (card) get('/api/x/react-' + card.dataset.act);
});

// 2. Hover menu.
if ($('#menu')) {
  $('#menu').addEventListener('mouseenter', () => { $('#reports').hidden = false; get('/api/x/menu-prefetch'); });
  $('#menu').addEventListener('mouseleave', () => { $('#reports').hidden = true; });
  $('#reports').addEventListener('click', () => get('/api/x/reports'));
}

// 3. Confirm, then delete.
$('#del-draft') && $('#del-draft').addEventListener('click', () => {
  if (confirm('Delete the draft?')) fetch('/api/x/draft', { method: 'DELETE' });
});

// 4. Navigate away; 5. change the route.
$('#go') && $('#go').addEventListener('click', () => { location.href = at('x', 'nav-target'); });
$('#route') && $('#route').addEventListener('click', () => { history.pushState({}, '', at('x', 'route')); renderRoute(); });

// 6. Logout in the page: it must never be clicked.
const logout = (marker) => () => {
  localStorage.clear();
  document.cookie = 'sid=; max-age=0; path=/';
  get('/api/x/' + marker);
};
$('#logout-btn') && $('#logout-btn').addEventListener('click', logout('logged-out'));
$('#signout') && $('#signout').addEventListener('click', logout('signed-out'));

// 8. Load more, for ever.
$('#more') && $('#more').addEventListener('click', (e) => {
  const b = e.target.closest('.load-more');
  if (!b) return;
  const n = Number(b.dataset.n);
  get('/api/x/more?n=' + n);
  b.insertAdjacentHTML('afterend', `<button class="load-more" data-n="${n + 10}">Show ${n + 10} more</button>`);
  b.remove();
});

// 9. Tabs.
$('#tab-billing') && $('#tab-billing').addEventListener('click', () => { $('#panel-billing').hidden = false; get('/api/x/tab-billing'); });
$('#tab-general') && $('#tab-general').addEventListener('click', () => { $('#panel-billing').hidden = true; });
$('#invoice') && $('#invoice').addEventListener('click', () => get('/api/x/invoice'));

// 10. Inside details.
$('#rebuild') && $('#rebuild').addEventListener('click', () => post('/api/x/rebuild', 'all=1'));

// 11. Closed shadow root.
customElements.define('x-widget', class extends HTMLElement {
  constructor() {
    super();
    const root = this.attachShadow({ mode: 'closed' });
    root.innerHTML = '<button>Widget action</button>';
    root.querySelector('button').addEventListener('click', () => get('/api/x/widget'));
  }
});

// 13. A hundred rows, a listener each.
if ($('#rows')) {
  for (let i = 1; i <= 100; i++) {
    const li = document.createElement('li');
    li.innerHTML = `Row ${i} <button class="row-open" data-id="${i}">View</button>`;
    li.querySelector('button').addEventListener('click', (e) => get('/api/x/row/' + e.target.dataset.id));
    $('#rows').appendChild(li);
  }
}

// 14. Enabled by input.
$('#coupon') && $('#coupon').addEventListener('input', () => { $('#apply').disabled = !$('#coupon').value; });
$('#apply') && $('#apply').addEventListener('click', () => get('/api/x/coupon?code=' + encodeURIComponent($('#coupon').value)));

// 15. A valid submit only: the browser checks the constraints first.
$('#signup') && $('#signup').addEventListener('submit', (e) => {
  e.preventDefault();
  post('/api/x/signup', new URLSearchParams(new FormData(e.target)).toString());
});

// 16. Enter.
$('#quick') && $('#quick').addEventListener('keydown', (e) => { if (e.key === 'Enter') get('/api/x/quick?q=' + encodeURIComponent(e.target.value)); });

// 17. dblclick, contextmenu.
$('#dbl') && $('#dbl').addEventListener('dblclick', () => get('/api/x/dbl'));
$('#ctx') && $('#ctx').addEventListener('contextmenu', (e) => { e.preventDefault(); get('/api/x/ctx'); });

// 18. Upload.
$('#avatar') && $('#avatar').addEventListener('change', (e) => {
  const fd = new FormData();
  fd.append('avatar', e.target.files[0]);
  fetch('/api/x/avatar', { method: 'POST', body: fd });
});

// 19. window.close; 20. a download.
$('#close') && $('#close').addEventListener('click', () => { get('/api/x/close'); window.close(); });
$('#export-file') && $('#export-file').addEventListener('click', async () => {
  await get('/api/x/export-file');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob(['a,b\n1,2\n'], { type: 'text/csv' }));
  a.download = 'export.csv';
  document.body.appendChild(a);
  a.click();
  a.remove();
});

// 22. Toolbar.
document.querySelectorAll('.tool').forEach((b) => b.addEventListener('click', () => get('/api/x/tool-' + b.textContent.toLowerCase())));

// 23. select; 24. checkbox; 25. a link that is a button.
$('#sort') && $('#sort').addEventListener('change', (e) => get('/api/x/sort?by=' + e.target.value.toLowerCase()));
$('#compact') && $('#compact').addEventListener('change', (e) => get('/api/x/toggle?on=' + e.target.checked));
$('#hash-link') && $('#hash-link').addEventListener('click', (e) => { e.preventDefault(); get('/api/x/hash-link'); });

// 27. role=button; 29. prefetch on hover.
$('#aria-btn') && $('#aria-btn').addEventListener('click', () => get('/api/x/aria'));
$('#docs-link') && $('#docs-link').addEventListener('mouseenter', () => get('/api/x/prefetch-docs'));

// 26. A button that comes late.
setTimeout(() => {
  if (!$('#late')) return;
  $('#late').innerHTML = '<button id="late-btn">Late button</button>';
  $('#late-btn').addEventListener('click', () => get('/api/x/late'));
}, 1200);

// 7. Infinite feed: three pages, then the end.
let page = 0;
if ($('#sentinel')) {
  const io = new IntersectionObserver(async (entries) => {
    if (!entries.some((e) => e.isIntersecting) || page >= 3) return;
    page++;
    await get('/api/x/feed?page=' + page);
    for (let i = 0; i < 20; i++) $('#feed').insertAdjacentHTML('beforeend', `<li>post ${page}.${i}</li>`);
    if (page >= 3) { io.disconnect(); $('#sentinel').textContent = 'the end'; }
  });
  io.observe($('#sentinel'));
}

// 12. The banner.
$('#accept') && $('#accept').addEventListener('click', () => { $('#banner').remove(); get('/api/x/consent-banner'); });
$('#under') && $('#under').addEventListener('click', () => get('/api/x/under'));

// --- Cases from the independent review (docs/gd4-explore-design.md §12).

// A popup, and a GET form into a new tab.
$('#popup') && $('#popup').addEventListener('click', () => window.open(at('x', 'popped')));

// A wizard with one "Next" button: three steps.
let wstep = 1;
$('#wiz-next') && $('#wiz-next').addEventListener('click', () => {
  get('/api/x/wizard/step' + wstep);
  if (wstep < 3) {
    wstep++;
    $('#wiz-body').innerHTML = `<label>Step ${wstep} field <input name="f${wstep}" class="wiz-f${wstep}"></label>`;
  } else {
    $('#wiz-body').textContent = 'done';
  }
});

// Rows that are clickable as a whole, named after their data.
$('#people') && $('#people').querySelectorAll('tr').forEach((tr) => tr.addEventListener('click', () => get('/api/x/person/' + tr.dataset.id)));

// A card with a handler of its own and a button inside.
$('#plan') && $('#plan').addEventListener('click', (e) => { if (e.target.closest('button')) return; get('/api/x/plan-card'); });
$('#plan-like') && $('#plan-like').addEventListener('click', () => get('/api/x/plan-like'));

// A link with a real href and a click handler that opens a dialog.
$('#terms') && $('#terms').addEventListener('click', (e) => { e.preventDefault(); get('/api/x/terms-dialog'); });

// Hover intent: the request comes after a delay set in mouseenter.
$('#intent') && $('#intent').addEventListener('mouseenter', () => setTimeout(() => get('/api/x/hover-intent'), 300));

// mousedown and keyup handlers.
$('#press') && $('#press').addEventListener('mousedown', () => get('/api/x/mousedown'));
$('#suggest') && $('#suggest').addEventListener('keyup', (e) => { if (e.target.value.length >= 2) get('/api/x/suggest?q=' + encodeURIComponent(e.target.value)); });

// An infinite list inside a scrolling box.
let boxPage = 0;
if ($('#box')) {
  $('#box').addEventListener('scroll', () => {
    const b = $('#box');
    if (b.scrollTop + b.clientHeight < b.scrollHeight - 10 || boxPage >= 2) return;
    boxPage++;
    get('/api/x/box?page=' + boxPage).then(() => { for (let i = 0; i < 10; i++) b.insertAdjacentHTML('beforeend', `<p>box ${boxPage}.${i}</p>`); });
  });
}

// A list that renders its nodes anew after each click.
function renderList() {
  $('#relist').innerHTML = ['Alpha', 'Beta'].map((n) => `<button class="re" data-n="${n}">Pick ${n}</button>`).join(' ');
  $('#relist').querySelectorAll('.re').forEach((b) => b.addEventListener('click', () => { get('/api/x/pick/' + b.dataset.n); renderList(); }));
}
$('#relist') && renderList();

// A modal whose Cancel comes before its Confirm.
$('#archive-all') && $('#archive-all').addEventListener('click', () => { $('#modal2').hidden = false; });
$('#modal2-cancel') && $('#modal2-cancel').addEventListener('click', () => { $('#modal2').hidden = true; });
$('#modal2-ok') && $('#modal2-ok').addEventListener('click', () => { $('#modal2').hidden = true; post('/api/x/archive-all', 'all=1'); });

// A custom upload button: input.click() on a hidden file input.
$('#pick-file') && $('#pick-file').addEventListener('click', () => $('#hidden-file').click());
$('#hidden-file') && $('#hidden-file').addEventListener('change', () => post('/api/x/custom-upload', 'f=1'));
// A folder picker made on the spot, never in the document (a DICOM
// viewer's "open folder"): webkitdirectory, then input.click().
$('#open-folder') && $('#open-folder').addEventListener('click', () => {
  const i = document.createElement('input');
  i.type = 'file';
  i.webkitdirectory = true;
  i.multiple = true;
  i.addEventListener('change', () => get('/api/x/folder-picked?n=' + i.files.length));
  i.click();
});

// Many alerts, then a request.
$('#alerts') && $('#alerts').addEventListener('click', () => { for (let i = 0; i < 25; i++) alert('a' + i); get('/api/x/after-alerts'); });

// A GET that does something.
$('#approve') && $('#approve').addEventListener('click', () => get('/api/x/orders/7/approve'));

// A form checked by script, not by the browser.
$('#jsform') && $('#jsform').addEventListener('submit', (e) => {
  e.preventDefault();
  const v = e.target.elements.nick.value;
  if (v.length < 3) { $('#jsform-err').textContent = 'too short'; return; }
  post('/api/x/jsform', 'nick=' + encodeURIComponent(v));
});

// Logouts in Vietnamese, and as an icon.
const vnLogout = logout('vn-logged-out');
$('#dang-xuat') && $('#dang-xuat').addEventListener('click', vnLogout);
$('#icon-logout') && $('#icon-logout').addEventListener('click', logout('icon-logged-out'));

// A dirty form that asks before the page is left.
$('#dirty') && $('#dirty').addEventListener('input', () => { window.onbeforeunload = (e) => { e.preventDefault(); e.returnValue = ''; }; });
