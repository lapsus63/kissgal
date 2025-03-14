import 'hammerjs';
import 'moment/min/locales';

import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import {APP_INITIALIZER, CUSTOM_ELEMENTS_SCHEMA, Injector, NgModule} from '@angular/core';

import {HttpLoaderFactory, LayoutModule} from './layout/layout.module';
import { AppComponent } from './app.component';
import { AppRoutingModule } from './app.routes';
import { HttpClient, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';

import { LOCATION_INITIALIZED } from '@angular/common';
import { TranslateLoader, TranslateModule, TranslateService } from '@ngx-translate/core';
import { UserService } from './shared/services/user.service';
import { LoggerService } from './shared/services/logger.service';
import {MatGridListModule} from "@angular/material/grid-list";
import {MatCardModule} from "@angular/material/card";

@NgModule({
  imports: [
    BrowserAnimationsModule,
    MatGridListModule,
    MatCardModule,
    LayoutModule,
    AppRoutingModule,
    TranslateModule.forRoot({
      loader: {
        provide: TranslateLoader,
        useFactory: HttpLoaderFactory,
        deps: [HttpClient]
      }
    })
  ],
  declarations: [AppComponent],
  providers: [
    { provide: APP_INITIALIZER, useFactory: appInitializerFactory, deps: [TranslateService, LoggerService, UserService, Injector], multi: true },
    provideHttpClient(withInterceptorsFromDi()),
    provideHttpClient()
  ],
  exports: [],
  schemas: [CUSTOM_ELEMENTS_SCHEMA],
  bootstrap: [AppComponent]
})
export class AppModule {}

/*
 * see https://github.com/ngx-translate/core/issues/517#issuecomment-299637956
 * Allows to call safely the synchronous method translateService.instant
 */
export function appInitializerFactory(translate: TranslateService, log: LoggerService, userService: UserService, injector: Injector) {
  return () =>
    new Promise<string>((resolve: Function) => {
      const locationInitialized = injector.get(LOCATION_INITIALIZED, Promise.resolve(null));
      locationInitialized.then(() => {
        const user = userService.getUserInformation();
        let language = (user && user.language ? user.language : '').toLowerCase();

        if (language !== 'fr') {
          language = 'en';
        }
        translate.setDefaultLang(language);

        // FIXME: https://rxjs.dev/deprecations/subscribe-arguments
        translate.use(language).subscribe({
          next: () => log.debug(`Successfully initialized '${language}' language.'`, 'AppModule'),
          error: (err) => log.error(`Problem with '${language}' language initialization.'`, err),
          complete: () => resolve(null)
        });
      });
    });
}
