import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable } from 'rxjs';
import {User} from "../model/user";
import {EnvConfigurationService} from "./envconf.service";

@Injectable({
  providedIn: 'root'
})
export class UserService {
  /** This allows for reactive programming, where components
   * can automatically update when the user state is modified. */
  private readonly userSubject = new BehaviorSubject<User>(null);
  user$ = this.userSubject.asObservable();

  endpoint = `${EnvConfigurationService.configuration.BACKEND_URL}${EnvConfigurationService.configuration.BACKEND_SUB_PATH}/user`;
  constructor(private readonly http: HttpClient) {}

  getUser(id: string): Observable<User> {
    return this.http.get<User>(`${this.endpoint}/${id}`);
  }

  getAuthorities(): Observable<string> {
    return this.http.get<string>(`${this.endpoint}/authorities`);
  }

  getLocaleList(): Observable<string[]> {
    return this.http.get<string[]>(`${this.endpoint}/locale`);
  }

  getCountryList(): Observable<string[]> {
    return this.http.get<string[]>(`${this.endpoint}/country`);
  }

  updateUser(user: User): Observable<User> {
    this.updateSessionStorage(user);
    return this.http.post<User>(`${this.endpoint}`, user);
  }

  getUserInformation(): User | null {
    const value = sessionStorage.getItem('user');
    return value ? JSON.parse(value) : null;
  }

  updateSessionStorage(userInformation: User): void {
    this.userSubject.next(userInformation);
    sessionStorage.setItem('user', JSON.stringify(userInformation));
  }

  hasRole(roles: string[]): boolean {
    return roles.includes(this.getUserInformation().role);
  }
}
