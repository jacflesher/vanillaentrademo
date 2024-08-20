package com.cdpaas.vanillaentrademo.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.web.SecurityFilterChain;
import java.util.Arrays;
import java.util.List;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.AUD;

@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration {

    JwtDecoder jwtDecoder;

    @Autowired
    public WebSecurityConfiguration(JwtDecoder decoratedJwtDecoder) {
        this.jwtDecoder = decoratedJwtDecoder;
    }

    @Value("${security.audienceid}")
    String audienceId;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        JwtDecoder wrappedJwtDecoder = wrapJwtDecoderWithAudienceCheck(jwtDecoder, audienceId);

        http
                .securityMatcher("/v1/**", "/actuator/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorizeHttpRequest -> {
                    authorizeHttpRequest.anyRequest().authenticated();
                })
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2ResourceServer -> {
                    oauth2ResourceServer.jwt(jwt -> {
                        jwt.decoder(jwtDecoder);
                        jwt.decoder(wrappedJwtDecoder);
                        jwt.jwtAuthenticationConverter(new JwtRolesConverter());
                    });
                });
        return http.build();
    }


    static JwtDecoder wrapJwtDecoderWithAudienceCheck(JwtDecoder jwtDecoderByIssuerUri, String... audienceId) {
        return (token) -> {

            Jwt jwt = jwtDecoderByIssuerUri.decode(token);

            List<String> audienceClaim = jwt.getClaimAsStringList(AUD);
            if (audienceClaim == null) {
                throw new JwtValidationException("JWT does not contain an 'aud' claim", List.of(new OAuth2Error("missing_aud")));
            }

//            System.out.println("Audience ID: " + Arrays.toString(audienceId));
//            System.out.println("JWT Claims: " + jwt.getClaims());
//            System.out.println("AUD: " + audienceClaim);

            boolean matchFound = Arrays.stream(audienceId).anyMatch(audienceClaim::contains);
            if (!matchFound) {
                throw new JwtValidationException("Audience field does not match: " + Arrays.toString(audienceId), List.of(new OAuth2Error("invalid_aud")));
            }

            return jwt;
        };
    }
}