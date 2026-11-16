import { format } from '../shared/format.js';

console.debug('JSHMARK:route:hidden');

export default function (app) {
  app.innerHTML = `<h1>${format('Hidden')}</h1>`;
}
