import {Component, inject} from '@angular/core';
import {RouterModule} from "@angular/router";
import {MenuComponent} from "./pages/menu/menu.component";
import {ThemeService} from "./shared/services/theme.service";
import {TranslateService} from "@ngx-translate/core";
import {Title} from "@angular/platform-browser";

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [MenuComponent, RouterModule],
  template: `
    <app-menu></app-menu>
    <main>
      <router-outlet></router-outlet>
    </main>
  `
})
export class AppComponent {
  private readonly themeService = inject(ThemeService);
  private readonly titleService = inject(Title);
  private readonly translateService = inject(TranslateService);

  constructor() {
    this.themeService.initializeTheme();

    const lang = localStorage.getItem('lang') || 'en';
    this.translateService.setDefaultLang('en');
    this.translateService.use(lang);

    // Mise à jour du titre lors du changement de langue
    this.translateService.onLangChange.subscribe(() => {
      this.updateTitle();
    });
    // Mise à jour du titre au démarrage
    this.updateTitle();
  }

  private updateTitle() {
    this.translateService.get('HomePage.Title').subscribe(title => {
      this.titleService.setTitle(title);
    });
  }


}
