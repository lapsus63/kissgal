import {Injectable} from '@angular/core';
import {Router} from '@angular/router';

@Injectable({
  providedIn: 'root'
})
export class AuthenticationWrapperService {

  constructor() {
  }

  public logout(router: Router): void {
    sessionStorage.setItem('logoutRedirectTo', router.url);
    sessionStorage.removeItem('logged');
  }

  public isAuthenticated(): boolean {
    return false;
  }

  public getRole(): string {
    return 'ROLE_ADMIN';
  }
}
