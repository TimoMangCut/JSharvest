import { Component } from '@angular/core';
import { Routes } from '@angular/router';

console.debug('JSHMARK:route:hidden-children');

@Component({
  selector: 'app-vault-index',
  template: '<h1>Vault</h1>',
})
class VaultIndexComponent {}

@Component({
  selector: 'app-vault-keys',
  template: '<h1>Vault keys</h1>',
})
class VaultKeysComponent {}

export const VAULT_ROUTES: Routes = [
  { path: '', component: VaultIndexComponent },
  { path: 'keys', component: VaultKeysComponent },
];
