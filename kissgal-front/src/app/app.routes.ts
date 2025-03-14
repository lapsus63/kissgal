import { NgModule } from '@angular/core';
import { PreloadAllModules, RouterModule, Routes } from '@angular/router';
import { LayoutComponent } from './layout/layout.component';
import { Title } from '@angular/platform-browser';
import { environment } from '../environments/environment';
import { AuthGuard } from './shared/utils/auth.guard';
import { ROLE_ANY } from './shared/utils/constants';
import {HomeComponent} from "./pages/home/home.component";

export const routes: Routes = [
    {
        path: '',
        component: LayoutComponent,
        children: [
            {
                path: '',
                data: { roles: ROLE_ANY },
                canActivate: [AuthGuard],
                loadChildren: () => import('./pages/home/home.module').then((m) => m.HomeModule)
            }
        ]
    },
    { path: '**', redirectTo: '', pathMatch: 'full' }
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
