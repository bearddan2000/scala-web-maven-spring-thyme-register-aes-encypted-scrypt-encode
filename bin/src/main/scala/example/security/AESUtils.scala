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

object AESUtils {

    val password = "@amG89>"
    val salt = "blacknoir"

    @throws (classOf[Exception])
    def generateKey(n :Int) :SecretKey = {
        val keyGenerator :KeyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(n)
        return keyGenerator.generateKey()
    }

    @throws (classOf[Exception] )
    def getKeyFromPassword() : SecretKey =
    {
        val factory :SecretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec :KeySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256)
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES")
    }

    def generateIv() :IvParameterSpec = {
        val iv = new Array[Byte](16)
        new SecureRandom().nextBytes(iv)
        return new IvParameterSpec(iv)
    }

    @throws ( classOf[Exception] )
    def encrypt(plainText :String, key :SecretKey, ivParameterSpec :IvParameterSpec) : String =
    {
      if(key == null)
      {
        println("key is null")
        //return ""
      }
      if(ivParameterSpec == null)
      {
        println("ivParameterSpec is null")
        //return ""
      }
      if(plainText == null)
      {
        println("plainText is null")
        //return ""
      }
        val cipher :Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

        if(cipher == null)
        {
          println("cipher is null")
      //    return ""
        }
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec)
        val cipherText = cipher.doFinal(plainText.getBytes())

          if(cipherText == null)
          {
            println("cipherText is null")
    //        return ""
          }
        return Base64.getEncoder().encodeToString(cipherText)
    }
}
