import {ActivatedRouteSnapshot, CanActivateFn, Router, RouterStateSnapshot, UrlTree} from '@angular/router';
import {AuthGuardData, createAuthGuard} from "keycloak-angular";
import {inject} from "@angular/core";

/*
 * https://github.com/mauriciovigolo/keycloak-angular
 */
const isAccessAllowed = async (
  route: ActivatedRouteSnapshot,
  _: RouterStateSnapshot,
  authData: AuthGuardData
): Promise<boolean | UrlTree> => {
  const { authenticated, grantedRoles } = authData;

  const requiredRoles = route.data['roles'];
  if (!requiredRoles) {
    console.warn("!requiredRole")
    return false;
  }

  const hasRequiredRole = (roles: string[]): boolean =>
    Object.values(grantedRoles.resourceRoles).some(roles => requiredRoles.includes(roles));

  if (authenticated && hasRequiredRole(requiredRoles)) {
    return true;
  }
  console.warn("!authenticated || !hasRequiredRole", requiredRoles)

  const router = inject(Router);
  return router.parseUrl('/forbidden');
};

export const canActivateAuthRole = createAuthGuard<CanActivateFn>(isAccessAllowed);

// @Injectable({
//   providedIn: 'root'
// })
// export class AuthGuard implements CanActivate {
//   constructor(private readonly authWrapperService: AuthenticationWrapperService, private readonly router: Router) {}
//
//   canActivate(next: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean> | Promise<boolean> | boolean {
//     if (state.url === '/' || this.authWrapperService.isAuthenticated()) {
//       const requiredRoles = next.data['roles']; /* string or string[] */
//       const userRole = this.authWrapperService.getRole();
//       return requiredRoles?.includes(userRole) === true;
//     } else {
//       this.router.navigate(['/']);
//       return false;
//     }
//   }
// }
