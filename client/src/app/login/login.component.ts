import {Component, inject, OnInit} from '@angular/core';
import {OAuthService} from 'angular-oauth2-oidc';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [],
  templateUrl: './login.component.html',
  styleUrl: './login.component.css'
})
export class LoginComponent implements OnInit{
  private oauthService = inject(OAuthService);

  ngOnInit(): void {
    this.oauthService.initCodeFlow();
  }

}
