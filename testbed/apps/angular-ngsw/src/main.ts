// Each case is a module that logs one JSHMARK:<category>:<name> marker at its
// top level, so the marker ends up in exactly one built file.
import { bootstrapApplication } from '@angular/platform-browser';
import { AppComponent } from './app/app.component';
import { appConfig } from './app/app.config';

console.debug('JSHMARK:entry:main');

bootstrapApplication(AppComponent, appConfig).catch((err) => console.error(err));
