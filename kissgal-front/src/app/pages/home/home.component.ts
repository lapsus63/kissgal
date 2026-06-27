import {Component, inject, OnInit} from '@angular/core';
import {CommonModule, NgOptimizedImage} from '@angular/common';
import {TranslateModule} from "@ngx-translate/core";
import {MatCardModule} from "@angular/material/card";
import {MatIconModule} from "@angular/material/icon";
import {MatButton, MatIconButton} from "@angular/material/button";
import {HasRolesDirective} from "keycloak-angular";
import Keycloak from "keycloak-js";
import {Gallery} from "../../shared/model/gallery";
import {GalleryService} from "../../shared/services/gallery.service";
import {GalleryComponent} from "../gallery/gallery.component";

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.scss'],
  imports: [CommonModule, TranslateModule, MatCardModule, NgOptimizedImage, MatIconModule, MatButton, MatIconButton, HasRolesDirective]
})
export class HomeComponent implements OnInit {
  private authService = inject(Keycloak);
  private galleryService = inject(GalleryService);


  publicGalleries: Gallery[];

  privateGalleries: Gallery[];

  ngOnInit(): void {
    this.galleryService.getPublicGalleries().subscribe({
      next: (galleries: Gallery[]) => this.publicGalleries = galleries,
      error: (error) => console.error(error)
    });
  }

  isAuthenticated(): boolean {
    return this.authService.authenticated ?? false;
  }


  onOpenGallery(gallery: Gallery) {
    console.error("Not implemented");
  }
}
