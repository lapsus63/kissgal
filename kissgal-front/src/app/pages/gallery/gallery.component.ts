import {Component, inject, OnInit} from '@angular/core';
import {User} from "../../shared/model/user";
import {UserService} from "../../shared/services/user.service";
import {TranslateModule} from "@ngx-translate/core";
import {ActivatedRoute} from "@angular/router";

@Component({
  imports: [
    TranslateModule
  ],
  templateUrl: 'gallery.component.html'
})
export class GalleryComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  galleryId: string | null = null;

  constructor(private readonly userService: UserService) {}

  ngOnInit(): void {
    this.route.paramMap.subscribe(params => {
      this.galleryId = params.get('id');
    });
  }
}
