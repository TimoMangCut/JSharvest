// The part of jQuery's interface the app uses: the calls are what count.
export const $ = {
  ajax(opts) { return fetch(opts.url, { method: opts.type || 'GET' }); },
  post(url, data) { return fetch(url, { method: 'POST', body: new URLSearchParams(data) }); },
};
