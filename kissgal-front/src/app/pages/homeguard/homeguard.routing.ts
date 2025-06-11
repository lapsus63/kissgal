import { RouterModule, Routes } from '@angular/router';

import { NgModule } from '@angular/core';
import { HomeguardComponent } from './homeguard.component';

const routes: Routes = [
  {
    path: '',
    component: HomeguardComponent
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class HomeguardRoutingModule {}
