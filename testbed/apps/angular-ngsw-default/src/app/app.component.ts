import { Component } from '@angular/core';
import { RouterLink, RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink],
  template: `
    <nav><a routerLink="/">Home</a></nav>
    <router-outlet />
  `,
})
export class AppComponent {
  // Polls for ever, like a real app checking for notifications.
  constructor() {
    setInterval(() => fetch('/api/ping'), 2000);
  }
}
