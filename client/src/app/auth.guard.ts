import {Injectable} from "@angular/core";
import {ActivatedRouteSnapshot, CanActivate, Router, RouterStateSnapshot} from "@angular/router";
import {OAuthService} from "angular-oauth2-oidc";


@Injectable()
export class AuthGuard implements CanActivate {

    constructor(private oauthService: OAuthService, private router: Router) {}

    canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Promise<boolean> {
        return this.oauthService
            .loadDiscoveryDocumentAndTryLogin()
            .then((res) => {
                return this.oauthService.hasValidIdToken() && this.oauthService.hasValidAccessToken()
            });
    }
}
