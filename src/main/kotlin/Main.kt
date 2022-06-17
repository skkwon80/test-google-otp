import java.util.*

fun main() {
    val key = GoogleOTP.generate("eddy", "legendaries.team")
    println("QR code URL: ${key.second}")
    println("Please input pin code.")
    while (true) {
        val scan = Scanner(System.`in`)
        val check = GoogleOTP.checkCode(scan.next().toInt(), key.first)
        if (check) break
        println("Invalid pin code.")
    }
    println("Success!")
}
