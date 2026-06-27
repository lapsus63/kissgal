import { Component, inject, OnInit } from '@angular/core';
import {User} from "../../shared/model/user";
import {UserService} from "../../shared/services/user.service";
import {TranslateModule} from "@ngx-translate/core";

@Component({
  imports: [
    TranslateModule
  ],
  templateUrl: 'homeguard.component.html'
})
export class HomeguardComponent implements OnInit {

  private readonly userService = inject(UserService);
  date: Date = new Date();
  userObject: User;
  number = 1234567.89;
  dateLocale: string;
  numberLocale: string;
  locale: string;

  ngOnInit(): void {
    this.userService.user$.subscribe((user) => {
      this.userObject = user;
      this.locale = this.userObject ? this.userObject.locale : 'en';
    });
  }
}
