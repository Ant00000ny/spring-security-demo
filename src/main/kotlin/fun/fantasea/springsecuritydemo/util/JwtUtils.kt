package `fun`.fantasea.springsecuritydemo.util

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.security.core.Authentication
import java.security.Security
import java.time.Instant
import java.util.*
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration


object JwtUtils {
    private val EXPIRATION_TIME = 5.minutes.toJavaDuration()
    /**
     * default jwt key
     */
    private val JWT_KEY = Keys.hmacShaKeyFor("fantasea.fun".repeat(10).toByteArray())

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    fun generateJwt(authentication: Authentication): String {
        val username = authentication.name
        val now = Instant.now()
        val token = Jwts.builder()
            .setSubject(username)
            .setIssuedAt(Date.from(now))
            .setExpiration(Date.from(now + EXPIRATION_TIME))
            .signWith(JWT_KEY, SignatureAlgorithm.HS256)
            .claim("testclaim", "testvalue")
            .compact()
        return token
    }

    @Throws(Exception::class)
    fun parseJwt(token: String): Jws<Claims> {
        return Jwts.parserBuilder()
            .setSigningKey(JWT_KEY)
            .build()
            .parseClaimsJws(token)
    }
}
