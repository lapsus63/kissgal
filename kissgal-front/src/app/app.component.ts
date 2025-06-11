import {Component, inject} from '@angular/core';
import {RouterModule} from "@angular/router";
import {MenuComponent} from "./pages/menu/menu.component";
import {ThemeService} from "./shared/services/theme.service";

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [MenuComponent, RouterModule],
  template: `
    <app-menu></app-menu>
    <main>
      <router-outlet></router-outlet>
    </main>
  `,
  styles: [``]
})
export class AppComponent {
  private themeService = inject(ThemeService);

  constructor() {
    this.themeService.initializeTheme();
  }

}
