package springsecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.function.Function;

@Service
public class JwtService {
    public static final String SECRET_KEY = "646d279acbaf33b4149b8487c98a4f4e6f208817f8da86ed81057c5060c2412f";

    public String getUserEmailFromJwtToken(String jwt) {
        return getClaim(jwt, Claims::getSubject);
    }

    public <T> T getClaim(String jwt,
                          Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(jwt);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String jwt) {
        return Jwts.parser()
                   .setSigningKey(getSignInKey())
                   .build()
                   .parseClaimsJwt(jwt)
                   .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean validateJwtToken(String jwt,
                                    UserDetails userDetails) {
    }
}
