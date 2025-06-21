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
  const { authenticated, keycloak, grantedRoles } = authData;

  const requiredRoles = route.data['roles'];
  if (!requiredRoles) {
    console.warn("!requiredRole")
    return false;
  }

  const hasRequiredRole = (roles: string[]): boolean =>
    Object.values(grantedRoles.resourceRoles[keycloak.clientId]).some(roles => requiredRoles.includes(roles));

  if (authenticated && hasRequiredRole(requiredRoles)) {
    return true;
  }
  console.warn("!authenticated || !hasRequiredRole", requiredRoles)

  const router = inject(Router);
  return router.parseUrl('/forbidden');
};

export const canActivateAuthRole = createAuthGuard<CanActivateFn>(isAccessAllowed);
