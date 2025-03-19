import { Injectable } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';
import { HttpErrorResponse } from '@angular/common/http';
import moment from 'moment';

@Injectable({
  providedIn: 'root'
})
export class LoggerService {
  constructor(private readonly tr: TranslateService) {}

  /** Log a message with the Debug level, can show an auto-closeable alert with clear style */
  debug(content: string, title: string, showAlert = false): void {
    console.debug(content, title);
    if (showAlert) {
      // this.alertService.showAlert({
      //   type: AlertType.clear,
      //   title,
      //   content,
      //   timestamp: moment().add(NOTIFICATION_CLOSE_DELAY_SEC, 'seconds').valueOf()
      // } as Alert);
    }
  }

  /** Log a message with the Error level, can show a fixed alert with critical style */
  error(content: string, o: Error | string, showAlert = false): void {
    console.error(content, o, new Error().stack);
    if (showAlert) {
      let title = o.toString();
      /* Replace technical information sent from server to user-friendly message */
      if (o instanceof HttpErrorResponse) {
        if (o.status) {
          title = this.tr.instant('Commons.Errors.InternalError');
        } else {
          title = this.tr.instant('Commons.Errors.UnreachableServer');
        }
      }
      // this.alertService.showAlert({
      //   type: AlertType.critical,
      //   title,
      //   content,
      //   timestamp: 0
      // } as Alert);
    }
  }

  /** Log a message with the Warning level, can show an auto-closable alert with strong style */
  warn(content: string, title: string, showAlert: boolean): void {
    console.warn(content, title);
    if (showAlert) {
      // this.alertService.showAlert({
      //   type: AlertType.strong,
      //   title,
      //   content,
      //   timestamp: moment().add(NOTIFICATION_CLOSE_DELAY_SEC, 'seconds').valueOf()
      // } as Alert);
    }
  }

  /** Log a message with the Info level, can show an auto-closeable alert with classical style */
  info(content: string, title: string, showAlert: boolean): void {
    console.info(content, title);
    if (showAlert) {
      // this.alertService.showAlert({
      //   type: AlertType.classical,
      //   title,
      //   content,
      //   timestamp: moment().add(NOTIFICATION_CLOSE_DELAY_SEC, 'seconds').valueOf()
      // } as Alert);
    }
  }

  /** Log a message with the Info level, can show an auto-closeable alert with success style */
  success(content: string, title: string, showAlert: boolean): void {
    console.info(content, title);
    if (showAlert) {
      // this.alertService.showAlert({
      //   type: AlertType.success,
      //   title,
      //   content,
      //   timestamp: moment().add(NOTIFICATION_CLOSE_DELAY_SEC, 'seconds').valueOf()
      // } as Alert);
    }
  }
}
