package example.security

import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.BadPaddingException
import javax.crypto.spec.IvParameterSpec
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
import java.util.Base64

import org.springframework.security.crypto.password.PasswordEncoder

class AESPasswordEncoder
extends org.springframework.security.crypto.scrypt.SCryptPasswordEncoder()
with PasswordEncoder {

    val ivParameterSpec :IvParameterSpec = AESUtils.generateIv()

    val key :SecretKey = AESUtils.getKeyFromPassword()

    override def encode(rawPassword :CharSequence) :String =
    {
      try {
        val res = AESUtils.encrypt(rawPassword.toString(), key, ivParameterSpec)
         return super.encode(res)
      } catch {
        case e: Exception => e.printStackTrace()

      }
      return super.encode(rawPassword)
    }

    override def matches(rawPassword :CharSequence, encodedPassword :String) :Boolean =
    {
     try {
       val res = AESUtils.encrypt(rawPassword.toString(), key, ivParameterSpec)
       return super.matches(res, encodedPassword)
     }catch{
      case e :Exception => {
        println("Passwords don't match")
        }
      }
      return false
    }
}
