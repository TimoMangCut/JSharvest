import { Component } from '@angular/core';

console.debug('JSHMARK:defer:idle');

// Imported only by an @defer (on idle) block, so it gets its own lazy chunk.
@Component({
  selector: 'app-defer-idle',
  template: '<p>Deferred (idle)</p>',
})
export class DeferIdleComponent {}
