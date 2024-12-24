package `fun`.fantasea.springsecuritydemo.controller

import `fun`.fantasea.springsecuritydemo.model.ResultVo
import org.springframework.http.ResponseEntity
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/common")
class CommonController {
    @GetMapping("/test")
    fun test(): ResponseEntity<ResultVo<Unit>> {
        val username = SecurityContextHolder.getContextHolderStrategy()
            .context
            .authentication
            .name
        return ResponseEntity.ok()
            .body(ResultVo.success("hello $username"))
    }

    @GetMapping("/testRole")
    fun testRole(): ResponseEntity<ResultVo<Unit>> {
        val username = SecurityContextHolder.getContextHolderStrategy()
            .context
            .authentication
            .name
        return ResponseEntity.ok()
            .body(ResultVo.success("hello $username"))
    }
}
