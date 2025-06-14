import {Component, effect, inject, OnInit} from '@angular/core';
import { RouterModule } from '@angular/router';

import {
  HasRolesDirective,
  KEYCLOAK_EVENT_SIGNAL,
  KeycloakEventType,
  typeEventArgs,
  ReadyArgs
} from 'keycloak-angular';
import Keycloak from "keycloak-js";
import {ThemeService} from "../../shared/services/theme.service";
import {MatIcon} from "@angular/material/icon";
import {AsyncPipe, NgIf, NgOptimizedImage} from "@angular/common";
import {MatIconButton} from "@angular/material/button";
import {MatMenu, MatMenuItem, MatMenuTrigger} from "@angular/material/menu";
import {TranslateModule, TranslateService} from "@ngx-translate/core";
import {STORAGE_KEY_LANG} from "../../shared/utils/constants";
import {Observable} from "rxjs";

@Component({
  selector: 'app-menu',
  imports: [RouterModule, HasRolesDirective, MatIcon, AsyncPipe, NgIf, NgOptimizedImage, MatIconButton, MatMenu, MatMenuItem, MatMenuTrigger, TranslateModule],
  templateUrl: './menu.component.html',
  styleUrls: ['./menu.component.scss'],
  standalone: true
})
export class MenuComponent implements OnInit {
  authenticated = false;
  keycloakStatus: string | undefined;
  isDarkMode$: Observable<boolean>;
  currentLanguage = 'en';
  currentFlag = 'flag_en.svg';

  private readonly keycloak = inject(Keycloak);
  private readonly keycloakSignal = inject(KEYCLOAK_EVENT_SIGNAL);
  private readonly themeService = inject(ThemeService);
  private readonly translateService = inject(TranslateService);

  constructor() {
    this.isDarkMode$ = this.themeService.darkMode$;
    effect(() => {
      const keycloakEvent = this.keycloakSignal();
      this.keycloakStatus = keycloakEvent.type;

      if (keycloakEvent.type === KeycloakEventType.Ready) {
        this.authenticated = typeEventArgs<ReadyArgs>(keycloakEvent.args);
      } else if (keycloakEvent.type === KeycloakEventType.AuthLogout) {
        this.authenticated = false;
      }
    });
  }

  ngOnInit(): void {
    this.currentLanguage = localStorage.getItem(STORAGE_KEY_LANG) || this.translateService.currentLang || 'en';
    this.updateLanguage();
  }

  toggleDarkMode(): void {
    this.themeService.toggleDarkMode();
  }

  login() {
    this.keycloak.login();
  }

  logout() {
    this.keycloak.logout();
  }

  /*
   * i18n
   */

  toggleLanguage() {
    if (this.currentLanguage === 'en') {
      this.currentLanguage = 'fr';
    } else {
        this.currentLanguage = 'en';
    }
    this.updateLanguage();
  }

  updateLanguage() {
    if (this.currentLanguage === 'fr') {
      this.currentFlag = 'flag_fr.svg';
    } else {
      this.currentFlag = 'flag_en.svg';
    }
    this.translateService.use(this.currentLanguage);
    localStorage.setItem(STORAGE_KEY_LANG, this.currentLanguage);
  }
}
