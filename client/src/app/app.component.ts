import {Component, inject} from '@angular/core';
import {Router, RouterOutlet} from '@angular/router';
import {LoginComponent} from './login/login.component';
import {DashboardComponent} from './dashboard/dashboard.component';
import {AuthConfig, OAuthService} from 'angular-oauth2-oidc';

const MODULES = [
    RouterOutlet,
    LoginComponent,
    DashboardComponent
  ]

const authCodeFlowConfig: AuthConfig = {
  // Url of the Identity Provider
  issuer: 'http://127.0.0.1:9999',
  requireHttps: false,
  // URL of the SPA to redirect the user to after login
  redirectUri: window.location.origin + '/dashboard',
  silentRefreshRedirectUri: window.location.origin + '/dashboard',
  // The SPA's id. The SPA is registerd with this id at the auth-server
  // clientId: 'server.code',
  clientId: 'client',
  // Just needed if your auth server demands a secret. In general, this
  // is a sign that the auth server is not configured with SPAs in mind
  // and it might not enforce further best practices vital for security
  // such applications.
  dummyClientSecret: 'secret',
  useHttpBasicAuth: true,
  responseType: 'code',
  // set the scope for the permissions the client should request
  // Important: Request offline_access to get a refresh token
  // The api scope is a usecase specific one
  scope: 'openid profile admin user offline_access',

  showDebugInformation: true,
};
@Component({
  selector: 'app-root',
  standalone: true,
  imports: [MODULES],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent {
  private oauthService = inject(OAuthService);
  private router = inject(Router);
  constructor() {
    console.log(authCodeFlowConfig.redirectUri);
    this.oauthService.configure(authCodeFlowConfig);
    this.oauthService.setupAutomaticSilentRefresh();
    this.oauthService.loadDiscoveryDocumentAndTryLogin({
      onTokenReceived: context => {
        console.log(context);
        this.router.navigateByUrl(authCodeFlowConfig.redirectUri!)
      }
    });
  };
}
