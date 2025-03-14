import { NgModule } from '@angular/core';

import { HomeRoutingModule } from './home.routing';
import { HomeComponent } from './home.component';
import {TranslateModule} from "@ngx-translate/core";

@NgModule({
  imports: [HomeRoutingModule, TranslateModule],
  providers: [],
  declarations: [HomeComponent]
})
export class HomeModule {}
