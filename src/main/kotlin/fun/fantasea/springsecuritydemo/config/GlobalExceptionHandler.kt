package `fun`.fantasea.springsecuritydemo.config

import `fun`.fantasea.springsecuritydemo.model.ResultVo
import `fun`.fantasea.springsecuritydemo.util.log
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.ResponseBody

@ControllerAdvice
class GlobalExceptionHandler {
    @ExceptionHandler(Exception::class)
    @ResponseBody
    fun handleException(e: Exception): ResultVo<Unit> {
        log.info("GlobalExceptionHandler processing exception...", e)
        return ResultVo.fail("error")
    }
}
