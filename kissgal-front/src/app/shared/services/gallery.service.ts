import {inject, Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {EnvConfigurationService} from "./envconf.service";
import {Gallery} from "../model/gallery";

@Injectable({
  providedIn: 'root'
})
export class GalleryService {

  private http = inject(HttpClient);

  endpoint = `${EnvConfigurationService.configuration.BACKEND_URL}${EnvConfigurationService.configuration.BACKEND_SUB_PATH}/gallery`;

  getPublicGalleries(): Observable<Gallery[]> {
    return this.http.get<any>(`${this.endpoint}/pub`);
  }
}
