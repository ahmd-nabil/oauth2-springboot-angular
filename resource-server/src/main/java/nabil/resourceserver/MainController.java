package nabil.resourceserver;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
public class MainController {

    @GetMapping("/main") // just authenticated
    public String main(Authentication authentication) {
        System.out.println(authentication.getAuthorities());
        return "Hello World!";
    }

    @PreAuthorize("hasAuthority('user')")
    @GetMapping("/user")
    public String user() {
        return "Hello User!";
    }

    @PreAuthorize("hasAuthority('admin')")
    @GetMapping("/admin")
    public String admin() {
        return "Hello Admin!";
    }

}
