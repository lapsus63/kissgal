import { Component, OnInit } from '@angular/core';
import {User} from "../../shared/model/user";
import {UserService} from "../../shared/services/user.service";

@Component({
  templateUrl: 'home.component.html',
  standalone: false
})
export class HomeComponent implements OnInit {
  date: Date = new Date();
  userObject: User;
  number = 1234567.89;
  dateLocale: string;
  numberLocale: string;
  locale: string;

  constructor(private readonly userService: UserService) {}

  ngOnInit(): void {
    this.userService.user$.subscribe((user) => {
      this.userObject = user;
      this.locale = this.userObject ? this.userObject.locale : 'en';
    });
  }
}
