package com.example.secureApplication.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ErrorController {
    @GetMapping("/error/403")
    public String error403(Model model) {
        model.addAttribute("message", "у вас нет доступа к этой странице (403 Forbidden)");
        return "error/403";
    }
    @GetMapping("/error/401")
    public String error401(Model model) {
        model.addAttribute("message", "Вы не авторизованы(401 Unauthorized)");
        return "error/401";
    }
}
