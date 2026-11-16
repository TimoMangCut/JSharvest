import { format } from '../shared/format.js';

console.debug('JSHMARK:route:about');

export default function (app) {
  app.innerHTML = `<h1>${format('About')}</h1>`;
}
