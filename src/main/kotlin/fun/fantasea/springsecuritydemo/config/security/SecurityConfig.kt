package `fun`.fantasea.springsecuritydemo.config.security

import com.fasterxml.jackson.databind.ObjectMapper
import `fun`.fantasea.springsecuritydemo.config.security.filter.JwtAuthenticationFilter
import `fun`.fantasea.springsecuritydemo.model.ResultVo
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.annotation.Bean
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.AuthenticationException
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.stereotype.Component
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import org.springframework.web.filter.CorsFilter


@Component
@EnableWebSecurity
class SecurityConfig(
    private val jwtAuthenticationFilter: JwtAuthenticationFilter,
) {
    @Bean
    fun filterChain(
        httpSecurity: HttpSecurity,
        objectMapper: ObjectMapper,
    ): SecurityFilterChain {
        httpSecurity.invoke {
            // disable default login methods
            httpBasic { disable() }
            formLogin { disable() }

            csrf { disable() }
            cors { }

            // disable session since using jwt
            sessionManagement {
                sessionCreationPolicy = SessionCreationPolicy.STATELESS
            }

            authorizeHttpRequests {
                authorize("/anon", permitAll)
                authorize("/api/v1/auth/**", permitAll)
                authorize("/api/v1/common/test", hasRole("USER"))
                authorize("/api/v1/common/testRole", hasRole("DOES_NOT_EXIST"))
                authorize(anyRequest, authenticated)
            }

            addFilterAfter<LogoutFilter>(jwtAuthenticationFilter)

            // this handles exceptions thrown inside filter -- which does not handle by global exception handler
            exceptionHandling {
                authenticationEntryPoint = AuthenticationEntryPoint { req: HttpServletRequest, resp: HttpServletResponse, ex: AuthenticationException ->
                    resp.status = HttpServletResponse.SC_UNAUTHORIZED
                    resp.writer.write(objectMapper.writeValueAsString(ResultVo.fail<Unit>(ex.message)))
                    return@AuthenticationEntryPoint
                }
            }
        }

        return httpSecurity.build()
    }

    @Bean
    fun corsFilter(): CorsFilter {
        val config = CorsConfiguration().apply {
            allowCredentials = true
            allowedOrigins = listOf("*")
            allowedHeaders = listOf("*")
            allowedMethods = listOf("*")
        }
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", config)
        return CorsFilter(source)
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder()
    }

    @Bean
    fun authenticationManager(authenticationConfiguration: AuthenticationConfiguration): AuthenticationManager {
        return authenticationConfiguration.authenticationManager
    }
}
