import { NgModule } from '@angular/core';

import { HomeguardRoutingModule } from './homeguard.routing';
import { HomeguardComponent } from './homeguard.component';
import {TranslateModule} from "@ngx-translate/core";

@NgModule({
  imports: [HomeguardRoutingModule, TranslateModule],
  providers: [],
  declarations: [HomeguardComponent]
})
export class HomeguardModule {}
