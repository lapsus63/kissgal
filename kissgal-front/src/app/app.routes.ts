import {Routes} from '@angular/router';
import {ROLE_USER} from './shared/utils/constants';
import {canActivateAuthRole} from "./shared/utils/auth.guard";
import {HomeComponent} from "./pages/home/home.component";
import {HomeguardComponent} from "./pages/homeguard/homeguard.component";
import {ForbiddenComponent} from "./pages/forbidden/forbidden.component";
import {NotFoundComponent} from "./pages/notfound/notfound.component";

export const routes: Routes = [
  { path: '', component: HomeComponent },
  {
    path: 'homeguard',
    component: HomeguardComponent,
    canActivate: [canActivateAuthRole],
    data: { roles: ROLE_USER }
  },
  { path: 'forbidden', component: ForbiddenComponent },
  { path: '**', component: NotFoundComponent }
];
