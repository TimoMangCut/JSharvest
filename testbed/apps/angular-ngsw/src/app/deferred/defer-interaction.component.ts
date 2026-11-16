import { Component } from '@angular/core';

console.debug('JSHMARK:defer:interaction');

// Imported only by an @defer (on interaction) block, so it gets its own lazy chunk.
@Component({
  selector: 'app-defer-interaction',
  template: '<p>Deferred (interaction)</p>',
})
export class DeferInteractionComponent {}
