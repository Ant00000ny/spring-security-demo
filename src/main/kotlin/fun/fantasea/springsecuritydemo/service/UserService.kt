package `fun`.fantasea.springsecuritydemo.service

import `fun`.fantasea.springsecuritydemo.model.User
import `fun`.fantasea.springsecuritydemo.model.UserRepository
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Component

@Component
class UserService(
    private val userRepository: UserRepository,
) : UserDetailsService {
    override fun loadUserByUsername(username: String?): User {
        if (username == null) {
            throw UsernameNotFoundException("username is null")
        }

        return userRepository.findByUsername(username)
            ?: throw UsernameNotFoundException("user $username not found")
    }
}
