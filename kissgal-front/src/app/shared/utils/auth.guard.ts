import { Injectable } from '@angular/core';
import { ActivatedRouteSnapshot, CanActivate, Router, RouterStateSnapshot } from '@angular/router';
import { Observable } from 'rxjs';
import { AuthenticationWrapperService } from '../services/authentication-wrapper.service';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {
  constructor(private readonly authWrapperService: AuthenticationWrapperService, private readonly router: Router) {}

  canActivate(next: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean> | Promise<boolean> | boolean {
    if (state.url === '/' || this.authWrapperService.isAuthenticated()) {
      const requiredRoles = next.data['roles']; /* string or string[] */
      const userRole = this.authWrapperService.getRole();
      return requiredRoles?.includes(userRole) === true;
    } else {
      this.router.navigate(['/']);
      return false;
    }
  }
}
