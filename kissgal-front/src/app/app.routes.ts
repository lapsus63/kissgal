import {NgModule} from '@angular/core';
import {PreloadAllModules, RouterModule, Routes} from '@angular/router';
import {LayoutComponent} from './layout/layout.component';
import {Title} from '@angular/platform-browser';
import {environment} from '../environments/environment';
import {ROLE_ANY, ROLE_USER} from './shared/utils/constants';
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

@NgModule({
    imports: [RouterModule.forRoot(routes, { preloadingStrategy: PreloadAllModules })],
    exports: [RouterModule]
})
export class AppRoutingModule {
    constructor(private readonly titleService: Title) {
        if (environment.production) {
            this.titleService.setTitle('KissGal');
        } else {
            this.titleService.setTitle('KissGal - ' + environment.instance);
        }
    }
}
