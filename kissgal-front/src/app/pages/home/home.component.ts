import {Component} from '@angular/core';
import {CommonModule} from '@angular/common';
import {MatDivider} from "@angular/material/divider";
import {TranslateModule} from "@ngx-translate/core";

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.scss'],
  imports: [CommonModule, MatDivider, TranslateModule]
})
export class HomeComponent {

}
