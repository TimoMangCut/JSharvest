import { Routes } from '@angular/router';
import { HomeComponent } from './home/home.component';

export const routes: Routes = [
  { path: '', component: HomeComponent },
  // Linked from the home page with routerLink.
  { path: 'about', loadComponent: () => import('./about/about.component').then((m) => m.AboutComponent) },
  // In this table only; no link anywhere.
  { path: 'hidden', loadComponent: () => import('./hidden/hidden.component').then((m) => m.HiddenComponent) },
  // A lazy child route group, in this table only; no link anywhere.
  { path: 'vault', loadChildren: () => import('./vault/vault.routes').then((m) => m.VAULT_ROUTES) },
  { path: '**', redirectTo: '' },
];
