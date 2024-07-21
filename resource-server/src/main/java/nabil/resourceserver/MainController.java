package nabil.resourceserver;


import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
public class MainController {

    @GetMapping(value = "/main", produces = "text/plain") // just authenticated
    public ResponseEntity<String> main(Authentication authentication) {
        System.out.println(authentication.getAuthorities());
        return ResponseEntity.ok("Hello World!");
    }

    @PreAuthorize("#authentication.authorities.?[authority.startsWith('user')].size() > 0")
    @GetMapping(value = "/user", produces = "text/plain")
    public ResponseEntity<String> user(Authentication authentication) {
        return ResponseEntity.ok("Hello User!");
    }

    @PreAuthorize("#authentication.authorities.?[authority.startsWith('admin')].size() > 0")
    @GetMapping(value = "/admin", produces = "text/plain")
    public ResponseEntity<String> admin(Authentication authentication) {
        return ResponseEntity.ok("Hello Admin!");
    }

    @PreAuthorize("#authentication.authorities.?[authority.startsWith('king')].size() > 0")
    @GetMapping(value = "/king", produces = "text/plain")
    public ResponseEntity<String> king(Authentication authentication) {
        return ResponseEntity.ok("Hello King!");
    }

}
