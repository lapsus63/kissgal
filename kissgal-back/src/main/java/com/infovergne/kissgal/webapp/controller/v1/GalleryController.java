package com.infovergne.kissgal.webapp.controller.v1;

import com.infovergne.kissgal.core.shared.model.ThreeState;
import com.infovergne.kissgal.webapp.dto.GalleryDto;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/gallery")
public class GalleryController {

    @GetMapping("/pub")
    public List<GalleryDto> getPublicGalleries() {
        GalleryDto g1 = GalleryDto.builder()
                .id(UUID.randomUUID().toString())
                .title("Title")
                .subTitle("Sub title")
                .favorite(ThreeState.UNDEFINED)
                .description("Gallery description in few words that may take some room on the card")
                .build();

        GalleryDto g2 = GalleryDto.builder()
                .id(UUID.randomUUID().toString())
                .title("Title 2")
                .subTitle("Sub title 2")
                .favorite(ThreeState.NO)
                .description("Gallery two description in few words that may take some room on the card")
                .build();

        return List.of(g1, g2);
    }
}
