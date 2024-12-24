package `fun`.fantasea.springsecuritydemo.model

import jakarta.persistence.*
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Repository

@Entity
@Table(name = "t_user")
data class User(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", columnDefinition = "text")
    val id: String? = null,
    @Column(name = "username", columnDefinition = "text")
    @get:JvmName("_username") // fix function signature clash with #getUsername()
    val username: String,
    /**
     * secured password. should be encrypted.
     */
    @Column(name = "password_secured", columnDefinition = "text")
    val passwordSecured: String,
) : UserDetails {
    override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
        return mutableSetOf(SimpleGrantedAuthority("ROLE_USER"))
    }

    override fun getPassword(): String {
        return passwordSecured
    }

    override fun getUsername(): String {
        return username
    }
}


@Repository
interface UserRepository : JpaRepository<User, String> {
    fun findByUsername(username: String): User?
}
