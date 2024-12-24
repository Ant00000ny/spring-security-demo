package `fun`.fantasea.springsecuritydemo.config.security.filter

import com.fasterxml.jackson.databind.ObjectMapper
import `fun`.fantasea.springsecuritydemo.model.ResultVo
import `fun`.fantasea.springsecuritydemo.model.UserRepository
import `fun`.fantasea.springsecuritydemo.util.JwtUtils
import `fun`.fantasea.springsecuritydemo.util.log
import io.jsonwebtoken.ExpiredJwtException
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtAuthenticationFilter(
    private val userRepository: UserRepository,
    private val objectMapper: ObjectMapper,
) : OncePerRequestFilter() {
    companion object {
        private const val TOKEN_GROUP_NAME = "token"
        /**
         * Bearer token format, see [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750).
         */
        private val REGEX = Regex("""Bearer (?<$TOKEN_GROUP_NAME>.+)""")
    }

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val token = request.getHeader(HttpHeaders.AUTHORIZATION)
            ?.let { REGEX.matchEntire(it) }
            ?.groups
            ?.get(TOKEN_GROUP_NAME)
            ?.value
        if (token == null) {
            // token not found, fallback this to other filters
            filterChain.doFilter(request, response)
            return
        }

        val username = try {
            JwtUtils.parseJwt(token).body.subject
        } catch (e: ExpiredJwtException) {
            response.status = HttpServletResponse.SC_UNAUTHORIZED
            response.writer.write(objectMapper.writeValueAsString(ResultVo.fail<Unit>("token expired")))
            return
        } catch (e: Exception) {
            log.info("jws authorize failed", e)
            response.status = HttpServletResponse.SC_UNAUTHORIZED
            response.writer.write(objectMapper.writeValueAsString(ResultVo.fail<Unit>("jws authorize failed")))
            return
        }

        val user = userRepository.findByUsername(username)
            ?: run {
                log.info("user $username not found, jws authorize failed")
                filterChain.doFilter(request, response)
                return
            }

        // put auth info into SecurityContextHolder
        val authentication = UsernamePasswordAuthenticationToken(user, null, user.authorities)
        authentication.details = WebAuthenticationDetailsSource().buildDetails(request)
        SecurityContextHolder.getContext().authentication = authentication
        filterChain.doFilter(request, response)
        return
    }
}
