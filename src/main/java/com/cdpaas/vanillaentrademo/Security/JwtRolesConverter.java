package com.cdpaas.vanillaentrademo.Security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.CollectionUtils;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class JwtRolesConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    protected static String rolesClaimName = "roles";
    protected static String rolesAuthorityPrefix = "ROLE_";

    public JwtRolesConverter() {
        log.debug("*** Using Ford Cloud Native JwtRolesConverter ***");
    }

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt token) {
        List<?> claimRoles = (List<?>) token.getClaims().get(rolesClaimName);
        if (CollectionUtils.isEmpty(claimRoles)) return new JwtAuthenticationToken(token, Collections.emptyList());

        return new JwtAuthenticationToken(token, claimRoles.stream().map(Object::toString).map(role ->
                new SimpleGrantedAuthority(rolesAuthorityPrefix + role)).collect(Collectors.toList()));
    }
}
