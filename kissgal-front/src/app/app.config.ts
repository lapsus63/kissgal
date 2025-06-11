import 'hammerjs';
import 'moment/min/locales';
import {ApplicationConfig, provideZoneChangeDetection} from '@angular/core';
import {routes} from './app.routes';
import {provideHttpClient, withInterceptors} from '@angular/common/http';
import {provideRouter} from "@angular/router";
import {provideKeycloakAngular} from "./keycloak.config";
import {includeBearerTokenInterceptor} from "keycloak-angular";


export const appConfig: ApplicationConfig = {
  providers: [
    provideKeycloakAngular(),
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideRouter(routes),
    provideHttpClient(withInterceptors([includeBearerTokenInterceptor]))
  ]
};

//
// @NgModule({
//   imports: [
//     BrowserAnimationsModule,
//     MatGridListModule,
//     MatCardModule,
//     LayoutModule,
//     AppRoutingModule,
//     TranslateModule.forRoot({
//       loader: {
//         provide: TranslateLoader,
//         useFactory: HttpLoaderFactory,
//         deps: [HttpClient]
//       }
//     })
//   ],
//   providers: [
//     provideKeycloakAngular(),
//     provideZoneChangeDetection({ eventCoalescing: true }),
//     provideRouter(routes),
//     { provide: APP_INITIALIZER, useFactory: appInitializerFactory, deps: [TranslateService, LoggerService, UserService, Injector], multi: true },
//     provideHttpClient(withInterceptors([includeBearerTokenInterceptor]))
//   ],
//   schemas: [CUSTOM_ELEMENTS_SCHEMA]
// })
// export class AppModule {}
//
// /*
//  * see https://github.com/ngx-translate/core/issues/517#issuecomment-299637956
//  * Allows to call safely the synchronous method translateService.instant
//  */
// export function appInitializerFactory(translate: TranslateService, log: LoggerService, userService: UserService, injector: Injector) {
//   return () =>
//     new Promise<string>((resolve: Function) => {
//       const locationInitialized = injector.get(LOCATION_INITIALIZED, Promise.resolve(null));
//       locationInitialized.then(() => {
//         const user = userService.getUserInformation();
//         let language = (user && user.language ? user.language : '').toLowerCase();
//
//         if (language !== 'fr') {
//           language = 'en';
//         }
//         translate.setDefaultLang(language);
//
//         // FIXME: https://rxjs.dev/deprecations/subscribe-arguments
//         translate.use(language).subscribe({
//           next: () => log.debug(`Successfully initialized '${language}' language.'`, 'AppModule'),
//           error: (err) => log.error(`Problem with '${language}' language initialization.'`, err),
//           complete: () => resolve(null)
//         });
//       });
//     });
// }
