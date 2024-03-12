package io.getarrays.securecapita.provider;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import io.getarrays.securecapita.domain.UserPrincipal;
import io.getarrays.securecapita.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
import static java.lang.System.currentTimeMillis;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;

@Component
@Slf4j
@RequiredArgsConstructor
public class TokenProvider {

    private final UserService userService;


    public static final String AUTHORITIES = "authorities";

    private static final String GET_ARRAYS_LLC = "GET_ARRAYS_LLC";

    private static final String CUSTOMER_MANAGEMENT_SERVICE = "CUSTOMER_MANAGEMENT_SERVICE";

    private static final long ACCESS_TOKEN_EXPIRATION_TIME = 432_000_000; //1_800_000;

    private static final long REFRESH_TOKEN_EXPIRATION_TIME = 432_000_000; // 5 days

    public static final String TOKEN_CANNOT_BE_VERIFIED = "Token cannot be verified";

    @Value("${jwt.secret}")
    private String secret;

    public String createAccessToken(UserPrincipal userPrincipal) {
        return JWT.create().withIssuer(GET_ARRAYS_LLC)
                .withAudience(CUSTOMER_MANAGEMENT_SERVICE)
                .withIssuedAt(new Date())
                .withSubject(userPrincipal.getUsername())
                .withArrayClaim(AUTHORITIES, getClaimsFromUser(userPrincipal))
                .withExpiresAt(new Date(currentTimeMillis() + ACCESS_TOKEN_EXPIRATION_TIME))
                .sign(HMAC512(secret.getBytes()));


    }

    public String createRefreshToken(UserPrincipal userPrincipal) {
        String[] claims = getClaimsFromUser(userPrincipal);
        return JWT.create().withIssuer(GET_ARRAYS_LLC)
                .withAudience(CUSTOMER_MANAGEMENT_SERVICE)
                .withIssuedAt(new Date())
                .withSubject(userPrincipal.getUsername())
                .withExpiresAt(new Date(currentTimeMillis() + REFRESH_TOKEN_EXPIRATION_TIME))
                .sign(HMAC512(secret.getBytes()));


    }

    public String getSubject (String token, HttpServletRequest request) {
        try {
            log.info("Verified token");
            return getJWTVerifier().verify(token).getSubject();
        }catch (TokenExpiredException exception) {
            request.setAttribute("expiredMessage", exception.getMessage());
        } catch (InvalidClaimException exception) {
            request.setAttribute("invalidClaim", exception.getMessage());
        } catch (Exception exception) {
            throw exception;
        }
        return token;
    }

    public List<GrantedAuthority> getAuthorities(String token) {
        String[] claims = getClaimsFromToken(token);
        return stream(claims).map(SimpleGrantedAuthority::new).collect(toList());
    }

    public Authentication getAuthentication(String email,
                                            List<GrantedAuthority>authorities,
                                            HttpServletRequest request) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthToken = new UsernamePasswordAuthenticationToken(
                userService.getUserByEmail(email), null, authorities
        );
        usernamePasswordAuthToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return usernamePasswordAuthToken;
    }

    public boolean isTokenValid (String email, String token) {
        JWTVerifier verifier = getJWTVerifier();
        return StringUtils.isNotEmpty(email) && !isTokenExpired(verifier, token);
    }

    private boolean isTokenExpired(JWTVerifier verifier, String token) {
        Date expiration = verifier.verify(token).getExpiresAt();
        return expiration.before(new Date());
    }

    private String[] getClaimsFromUser(UserPrincipal userPrincipal) {
        return userPrincipal.getAuthorities().stream().map(GrantedAuthority::getAuthority).toArray(String[]::new);
    }

    private String[] getClaimsFromToken(String token) {
        JWTVerifier verifier = getJWTVerifier();
        return verifier.verify(token).getClaim(AUTHORITIES).asArray(String.class);
    }

    private JWTVerifier getJWTVerifier() {
        JWTVerifier verifier;
        try
        {
            Algorithm algorithm = HMAC512(secret);
            verifier = JWT.require(algorithm).withIssuer(GET_ARRAYS_LLC).build();
        }catch(JWTVerificationException exception)
        {
            throw new JWTVerificationException(TOKEN_CANNOT_BE_VERIFIED);
        }
        return verifier;
    }
}
