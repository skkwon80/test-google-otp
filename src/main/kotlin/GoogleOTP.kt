import org.apache.commons.codec.binary.Base32
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.util.*
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

class GoogleOTP {
    companion object {
        fun generate(account: String, host: String): Pair<String, String> {
            val secretKey = Random.nextBytes(ByteArray(5 + 5 * 5)).copyOf(10)
            val encodedKey = String(Base32().encode(secretKey))
            val url = getQRCodeURL(account, host, encodedKey)

            return Pair(encodedKey, url)
        }

        fun checkCode(pinCode: Int, otpKey: String): Boolean {
            val wave = Date().time / TimeUnit.SECONDS.toMillis(30)
            try {
                val decodedKey = Base32().decode(otpKey)
                val window = 3
                for (i in -window..window) {
                    val hash = verifyCode(decodedKey, wave + i).toLong()
                    if (hash == pinCode.toLong()) {
                        return true
                    }
                }
            } catch (e: InvalidKeyException) {
                e.printStackTrace()
            } catch (e: NoSuchAlgorithmException) {
                e.printStackTrace()
            }
            return false
        }

        @Throws(NoSuchAlgorithmException::class, InvalidKeyException::class)
        private fun verifyCode(key: ByteArray, t: Long): Int {
            val data = ByteArray(8)
            var value = t
            run {
                var i = 8
                while (i-- > 0) {
                    data[i] = value.toByte()
                    value = value ushr 8
                }
            }
            val signKey = SecretKeySpec(key, "HmacSHA1")
            val mac = Mac.getInstance("HmacSHA1")
            mac.init(signKey)
            val hash = mac.doFinal(data)
            val offset = hash[20 - 1].toInt() and 0xF

            // We're using a long because Java hasn't got unsigned int.
            var truncatedHash: Long = 0
            for (i in 0..3) {
                truncatedHash = truncatedHash shl 8
                // We are dealing with signed bytes:
                // we just keep the first byte.
                truncatedHash = truncatedHash or (hash[offset + i].toInt() and 0xFF).toLong()
            }
            truncatedHash = truncatedHash and 0x7FFFFFFFL
            truncatedHash %= 1000000

            return truncatedHash.toInt()
        }

        private fun getQRCodeURL(account: String, host: String, secretKey: String): String {
            val params = listOf(
                "cht=qr",
                "chs=200x200",
                "chl=otpauth://totp/$account@$host?secret=$secretKey",
            )
            return "https://chart.apis.google.com/chart?${params.joinToString("&")}"
        }
    }
}
