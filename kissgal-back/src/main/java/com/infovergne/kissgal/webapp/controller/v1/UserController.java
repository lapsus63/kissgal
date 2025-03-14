package com.infovergne.kissgal.webapp.controller.v1;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/user")
public class UserController {

    @GetMapping("")
    public List<String> getAllUsers() {
        return List.of("Solenne", "Olivier", "Victor", "Clémence");
    }
}
