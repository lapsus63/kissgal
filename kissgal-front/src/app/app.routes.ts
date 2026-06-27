import {Routes} from '@angular/router';
import {ROLE_USER} from './shared/utils/constants';
import {canActivateAuthRole} from "./shared/utils/auth.guard";
import {HomeComponent} from "./pages/home/home.component";
import {HomeguardComponent} from "./pages/homeguard/homeguard.component";
import {ForbiddenComponent} from "./pages/redirect/forbidden/forbidden.component";
import {NotFoundComponent} from "./pages/redirect/notfound/notfound.component";
import {GalleryComponent} from "./pages/gallery/gallery.component";

export const routes: Routes = [
  { path: '', component: HomeComponent },
  {
    path: 'gallery/:id',
    component: GalleryComponent
  },
  {
    path: 'homeguard',
    component: HomeguardComponent,
    canActivate: [canActivateAuthRole],
    data: { roles: ROLE_USER }
  },
  { path: 'forbidden', component: ForbiddenComponent },
  { path: '**', component: NotFoundComponent }
];
