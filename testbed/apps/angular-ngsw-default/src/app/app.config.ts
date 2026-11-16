import { ApplicationConfig, isDevMode, provideZoneChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideServiceWorker } from '@angular/service-worker';
import { routes } from './app.routes';

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideRouter(routes),
    // Angular's default strategy: register once the app is stable, or after
    // 30 s. The polling in AppComponent keeps the app from ever being stable,
    // as real apps with polling or sockets do, so the worker only registers
    // after 30 s, later than a passive crawl waits.
    provideServiceWorker('ngsw-worker.js', {
      enabled: !isDevMode(),
    }),
  ],
};
