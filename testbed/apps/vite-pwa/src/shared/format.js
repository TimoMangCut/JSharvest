// Shared by /about and /hidden, so Vite splits it into its own chunk and
// lists it in __vite__mapDeps for both routes.
console.debug('JSHMARK:shared:format');

export const format = (s) => `[${s}]`;
