package `fun`.fantasea.springsecuritydemo.model

data class ResultVo<T>(
    val code: Int,
    val message: String?,
    val data: T?,
) {
    companion object {
        fun <T> success(message: String? = null, data: T? = null): ResultVo<T> = ResultVo(0, message, data)
        fun <T> fail(message: String? = null, data: T? = null): ResultVo<T> = ResultVo(-1, message, data)
    }
}
