import * as moment from 'moment';
import {Component, OnInit} from '@angular/core';
import {environment} from '../../environments/environment';
import {User} from '../shared/model/user';
import {Router} from '@angular/router';
import {TranslateService} from '@ngx-translate/core';
import {UserService} from '../shared/services/user.service';
import {LoggerService} from '../shared/services/logger.service';
import {ROLE_ADMIN, ROLE_ANY} from '../shared/utils/constants';

@Component({
  templateUrl: './layout.component.html',
  styleUrls: ['./layout.component.scss'],
  standalone: false
})
export class LayoutComponent implements OnInit {

  year = moment.utc().format('YYYY');
  version = environment.version;
  title = environment.app_fullname;
  user: User = null;
  darkMode = false;
  language: string;
  userObject: User;

  tiles = [
    { text: 'One', cols: 3, rows: 1 },
    { text: 'Two', cols: 1, rows: 2 },
    { text: 'Three', cols: 1, rows: 1 },
    { text: 'Four', cols: 2, rows: 1 }
  ];

  /* Role management */
  protected readonly ROLE_ADMIN = ROLE_ADMIN;
  protected readonly ROLE_ANY = ROLE_ANY;

  constructor(
    private readonly translate: TranslateService,
    private readonly router: Router,
    private readonly userService: UserService,
    protected log: LoggerService
  ) {}

  /**
   * On init
   */
  ngOnInit(): void {

  }

  /**
   * set the language
   */
  setLanguage(lang: string) {
    this.translate.use(lang);
    this.userObject.language = lang;
    this.updateUser(this.userObject);
  }

  updateUser(userInformation: User): void {
    this.userService.updateUser(userInformation).subscribe({
      next: () => {
        this.log.info(this.translate.instant('TODO'), this.translate.instant('TODO'), false);
      }
    });
  }

  hasAnyRole(requiredRoles: string | string[]) {
    const userRole = 'ROLE_ADMIN';
    return requiredRoles?.includes(userRole) === true;
  }
}
