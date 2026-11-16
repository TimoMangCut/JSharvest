console.debug('JSHMARK:route:about');

export default function (app) {
  app.innerHTML = '<h1>About</h1><div style="height:3000px">long page</div><div id="end">end</div>';
  // Loads only when the bottom of the page scrolls into view.
  const io = new IntersectionObserver((entries) => {
    if (entries.some((e) => e.isIntersecting)) {
      io.disconnect();
      import('../features/comments.js');
    }
  });
  io.observe(app.querySelector('#end'));
}
