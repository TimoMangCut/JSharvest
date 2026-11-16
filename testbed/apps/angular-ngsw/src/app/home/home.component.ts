import { Component, ViewContainerRef, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { DeferIdleComponent } from '../deferred/defer-idle.component';
import { DeferInteractionComponent } from '../deferred/defer-interaction.component';

// Part of the main bundle; carries no marker of its own.
@Component({
  selector: 'app-home',
  imports: [RouterLink, DeferIdleComponent, DeferInteractionComponent],
  template: `
    <h1>Home</h1>
    <p><a routerLink="/about">About</a></p>
    <button id="report" (click)="loadReport()">Show report</button>

    @defer (on idle) {
      <app-defer-idle />
    } @placeholder {
      <p>Loading tips…</p>
    }

    @defer (on interaction) {
      <app-defer-interaction />
    } @placeholder {
      <button id="details">Show details</button>
    }
  `,
})
export class HomeComponent {
  private readonly vcr = inject(ViewContainerRef);

  // The report chunk is only imported once the button is clicked.
  async loadReport() {
    const { ReportComponent } = await import('../report/report.component');
    this.vcr.createComponent(ReportComponent);
  }
}
