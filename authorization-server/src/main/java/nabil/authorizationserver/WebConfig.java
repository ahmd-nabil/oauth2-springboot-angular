package nabil.authorizationserver;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebMvc
public class WebConfig implements WebMvcConfigurer {

	@Override
	public void addCorsMappings(CorsRegistry registry) {
		registry.addMapping("/**")
			.allowedOrigins("http://127.0.0.1:4200")
			.allowedMethods("*")
			.allowedHeaders("*")
			.exposedHeaders("*")
			.allowCredentials(true)
			.maxAge(3600);
	}
}