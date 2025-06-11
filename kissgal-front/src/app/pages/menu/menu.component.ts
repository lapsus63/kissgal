import { Component, effect, inject } from '@angular/core';
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
import {AsyncPipe} from "@angular/common";

@Component({
  selector: 'app-menu',
  imports: [RouterModule, HasRolesDirective, MatIcon, AsyncPipe],
  templateUrl: './menu.component.html',
  styleUrls: ['./menu.component.scss']
})
export class MenuComponent {
  authenticated = false;
  keycloakStatus: string | undefined;
  private readonly keycloak = inject(Keycloak);
  private readonly keycloakSignal = inject(KEYCLOAK_EVENT_SIGNAL);
  private readonly themeService = inject(ThemeService);

  isDarkMode$ = this.themeService.darkMode$;

  constructor() {
    effect(() => {
      const keycloakEvent = this.keycloakSignal();

      this.keycloakStatus = keycloakEvent.type;

      if (keycloakEvent.type === KeycloakEventType.Ready) {
        this.authenticated = typeEventArgs<ReadyArgs>(keycloakEvent.args);
      }

      if (keycloakEvent.type === KeycloakEventType.AuthLogout) {
        this.authenticated = false;
      }
    });
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
}
