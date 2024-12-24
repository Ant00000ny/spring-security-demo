package `fun`.fantasea.springsecuritydemo.controller

import `fun`.fantasea.springsecuritydemo.model.ResultVo
import `fun`.fantasea.springsecuritydemo.model.User
import `fun`.fantasea.springsecuritydemo.model.UserRepository
import `fun`.fantasea.springsecuritydemo.util.JwtUtils
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController


@RestController
@RequestMapping("/api/v1/auth")
class AuthenticationController(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val authenticationManager: AuthenticationManager,
) {
    @PostMapping("/register")
    fun register(@RequestBody registerDto: RegisterDto): ResponseEntity<ResultVo<*>> {
        // check if user already exists
        val user = userRepository.findByUsername(registerDto.username)
        if (user != null) {
            return ResponseEntity.ok()
                .body(ResultVo.fail<Unit>("user ${registerDto.username} already exists"))
        }

        // persistent new user
        val newUser = User(
            id = null,
            username = registerDto.username,
            passwordSecured = passwordEncoder.encode(registerDto.password),
        )
        userRepository.save(newUser)

        return ResponseEntity.ok()
            .body(ResultVo.success<Unit>("success"))
    }

    @PostMapping("/login")
    fun login(@RequestBody loginDto: LoginDto): ResponseEntity<ResultVo<LoginVo>> {
        // this calls loadUserByUsername and validates user password, throws BadCredentialsException if validate fails
        val authentication = authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken(
                loginDto.username,
                loginDto.password,
            )
        )

        // generate jwt
        val context = SecurityContextHolder.getContextHolderStrategy().context
        context.authentication = authentication
        val token = JwtUtils.generateJwt(authentication)
        val user = userRepository.findByUsername(authentication.name)
            ?: return ResponseEntity.ok()
                .body(ResultVo.fail("user ${loginDto.username} not found"))

        return ResponseEntity.ok()
            .body(ResultVo.success("login success", LoginVo(user.id!!, user.username, token)))
    }
}


data class RegisterDto(
    val username: String,
    val password: String,
)

data class LoginDto(
    val username: String,
    val password: String,
)

data class LoginVo(
    val id: String,
    val username: String,
    val token: String,
)
