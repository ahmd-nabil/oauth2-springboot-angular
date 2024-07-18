package nabil.resourceserver;

import java.security.Principal;

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

    @PreAuthorize("#principal.authorities.?[authority.startsWith('user')].size() > 0")
    @GetMapping("/user")
    public String user(Principal principal) {
        return "Hello User!";
    }

    @PreAuthorize("#principal.authorities.?[authority.startsWith('admin')].size() > 0")
    @GetMapping("/admin")
    public String admin(Principal principal) {
        return "Hello Admin!";
    }

    @PreAuthorize("#principal.authorities.?[authority.startsWith('king')].size() > 0")
    @GetMapping("/king")
    public String king(Principal principal) {
        return "Hello King!";
    }

}
