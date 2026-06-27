package com.infovergne.kissgal.webapp.dto;

import com.infovergne.kissgal.core.shared.model.ThreeState;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class GalleryDto {

    private String id;
    private String title;
    private String subTitle;
    private String description;
    private ThreeState favorite;
}
