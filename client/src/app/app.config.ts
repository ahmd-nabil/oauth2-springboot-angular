import {ApplicationConfig} from '@angular/core';
import {provideRouter} from '@angular/router';

import {routes} from './app.routes';
import {HTTP_INTERCEPTORS, provideHttpClient, withInterceptorsFromDi} from '@angular/common/http';
import {DefaultOAuthInterceptor, provideOAuthClient} from 'angular-oauth2-oidc';
import {AuthGuard} from './auth.guard';


export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes),
    provideHttpClient(withInterceptorsFromDi()),
    {provide:HTTP_INTERCEPTORS, useClass: DefaultOAuthInterceptor, multi:true},
    {provide: AuthGuard, useClass: AuthGuard},
    // {provide:HTTP_INTERCEPTORS, useClass: OAuthNoopResourceServerErrorHandler, multi:true},
    provideOAuthClient({
      resourceServer: {
        allowedUrls: ['http://127.0.0.1:8080'],
        sendAccessToken: true
      }
    }),
  ]
};
