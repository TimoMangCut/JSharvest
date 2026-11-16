// An axios-like client: a base URL, and one method per HTTP verb.
export function createClient({ baseURL, headers = {} }) {
  const call = (method, url, data, config = {}) => {
    const q = config.params ? '?' + new URLSearchParams(config.params) : '';
    return fetch(baseURL + url + q, {
      method,
      headers: { 'Content-Type': 'application/json', ...headers, ...config.headers },
      body: data === undefined ? undefined : JSON.stringify(data),
      credentials: 'include',
    }).then((r) => r.json());
  };
  return {
    get: (url, config) => call('GET', url, undefined, config),
    delete: (url, config) => call('DELETE', url, undefined, config),
    post: (url, data, config) => call('POST', url, data, config),
    put: (url, data, config) => call('PUT', url, data, config),
  };
}

export const http = createClient({ baseURL: '/api', headers: { 'X-Client': 'conduit' } });

// A wrapper that takes the method first, as many apps write their own.
export function request(method, url, body) {
  return fetch(url, { method, body: body && JSON.stringify(body) });
}
