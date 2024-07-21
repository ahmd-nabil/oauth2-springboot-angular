import {HttpClient} from '@angular/common/http';
import {Component, inject, OnInit} from '@angular/core';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.css'
})
export class DashboardComponent implements OnInit{
  private http = inject(HttpClient);
  public title = "";
  public title2 = "";
  public title3 = "";
  public title4 = "";
  ngOnInit(): void {
    this.http.get("http://127.0.0.1:8080/main", {responseType: 'text'}).subscribe(res => this.title = res);
    this.http.get("http://127.0.0.1:8080/user", {responseType: 'text'}).subscribe(res => this.title2 = res);
    this.http.get("http://127.0.0.1:8080/admin", {responseType: 'text'}).subscribe(res => this.title3 = res);
    this.http.get("http://127.0.0.1:8080/king", {responseType: 'text'}).subscribe(res => this.title4 = res);
  }
}
