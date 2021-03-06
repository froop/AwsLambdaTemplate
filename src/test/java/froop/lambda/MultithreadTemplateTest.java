package froop.lambda;

import static org.junit.jupiter.api.Assertions.*;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Test;

import froop.lambda.MultithreadTemplate.CipherCondition;

class MultithreadTemplateTest {

  @Test
  void testExecuteMin() throws GeneralSecurityException {
    String encrypted = encrypt("1", "");
    CipherCondition cond = new CipherCondition("Blowfish", "0123456789", "", Base64.decodeBase64(encrypted));
    MultithreadTemplate target = new MultithreadTemplate(cond, 1, 1);
    assertEquals("1", target.execute());
  }

  @Test
  void testExecuteMax() throws GeneralSecurityException {
    String encrypted = encrypt("9", "");
    CipherCondition cond = new CipherCondition("Blowfish", "0123456789", "", Base64.decodeBase64(encrypted));
    MultithreadTemplate target = new MultithreadTemplate(cond, 10, 1);
    assertEquals("9", target.execute());
  }

  @Test
  void testExecuteNotFinish() throws GeneralSecurityException {
    String encrypted = encrypt("10", "");
    CipherCondition cond = new CipherCondition("Blowfish", "0123456789", "", Base64.decodeBase64(encrypted));
    MultithreadTemplate target = new MultithreadTemplate(cond, 10, 1);
    assertEquals("", target.execute());
  }

  @Test
  void testExecuteWidth2() throws GeneralSecurityException {
    String encrypted = encrypt("12", "");
    CipherCondition cond = new CipherCondition("Blowfish", "0123456789", "", Base64.decodeBase64(encrypted));
    MultithreadTemplate target = new MultithreadTemplate(cond, 100, 1);
    assertEquals("12", target.execute());
  }

  @Test
  void testExecuteWidth3() throws GeneralSecurityException {
    String encrypted = encrypt("123", "");
    CipherCondition cond = new CipherCondition("Blowfish", "0123456789", "", Base64.decodeBase64(encrypted));
    MultithreadTemplate target = new MultithreadTemplate(cond, 1000, 1);
    assertEquals("123", target.execute());
  }

  @Test
  void testExecuteDivisionNot1() throws GeneralSecurityException {
    String encrypted = encrypt("1234", "");
    CipherCondition cond = new CipherCondition("Blowfish", "0123456789", "", Base64.decodeBase64(encrypted));
    MultithreadTemplate target = new MultithreadTemplate(cond, 1000, 4001);
    assertEquals("1234", target.execute());
  }

  @Test
  void testPlainText() throws GeneralSecurityException {
    String encrypted = encrypt("987", "abc123");
    CipherCondition cond = new CipherCondition("Blowfish", "0123456789", "abc123", Base64.decodeBase64(encrypted));
    MultithreadTemplate target = new MultithreadTemplate(cond, 1000, 1);
    assertEquals("987", target.execute());
  }

  @Test
  void testToText_charSet2() {
    String charSet = "01";
    int i = 0;
    assertEquals("", MultithreadTemplate.toText(charSet, i++));
//    assertEquals("0", MultithreadTemplate.toText(charSet, i++));
    assertEquals("1", MultithreadTemplate.toText(charSet, i++));
//    assertEquals("00", MultithreadTemplate.toText(charSet, i++));
    assertEquals("01", MultithreadTemplate.toText(charSet, i++));
    assertEquals("11", MultithreadTemplate.toText(charSet, i++));
//    assertEquals("000", MultithreadTemplate.toText(charSet, i++));
    assertEquals("001", MultithreadTemplate.toText(charSet, i++));
    assertEquals("101", MultithreadTemplate.toText(charSet, i++));
    assertEquals("011", MultithreadTemplate.toText(charSet, i++));
    assertEquals("111", MultithreadTemplate.toText(charSet, i++));
//    assertEquals("0000", MultithreadTemplate.toText(charSet, i++));
    assertEquals("0001", MultithreadTemplate.toText(charSet, i++));
    assertEquals("1001", MultithreadTemplate.toText(charSet, i++));
    assertEquals("0101", MultithreadTemplate.toText(charSet, i++));
    assertEquals("1101", MultithreadTemplate.toText(charSet, i++));
    assertEquals("0011", MultithreadTemplate.toText(charSet, i++));
    assertEquals("1011", MultithreadTemplate.toText(charSet, i++));
    assertEquals("0111", MultithreadTemplate.toText(charSet, i++));
    assertEquals("1111", MultithreadTemplate.toText(charSet, i++));
//    assertEquals("00000", MultithreadTemplate.toText(charSet, i++));
    assertEquals("00001", MultithreadTemplate.toText(charSet, i++));
  }

  @Test
  void testToText_charSet3() {
    String charSet = "012";
    int i = 0;
    assertEquals("", MultithreadTemplate.toText(charSet, i++));
//    assertEquals("0", MultithreadTemplate.toText(charSet, i++));
    assertEquals("1", MultithreadTemplate.toText(charSet, i++));
    assertEquals("2", MultithreadTemplate.toText(charSet, i++));
//    assertEquals("00", MultithreadTemplate.toText(charSet, i++));
    assertEquals("01", MultithreadTemplate.toText(charSet, i++));
    assertEquals("11", MultithreadTemplate.toText(charSet, i++));
    assertEquals("21", MultithreadTemplate.toText(charSet, i++));
    assertEquals("02", MultithreadTemplate.toText(charSet, i++));
    assertEquals("12", MultithreadTemplate.toText(charSet, i++));
    assertEquals("22", MultithreadTemplate.toText(charSet, i++));
//    assertEquals("000", MultithreadTemplate.toText(charSet, i++));
    assertEquals("001", MultithreadTemplate.toText(charSet, i++));
    assertEquals("101", MultithreadTemplate.toText(charSet, i++));
    assertEquals("201", MultithreadTemplate.toText(charSet, i++));
    assertEquals("011", MultithreadTemplate.toText(charSet, i++));
    assertEquals("111", MultithreadTemplate.toText(charSet, i++));
    assertEquals("211", MultithreadTemplate.toText(charSet, i++));
    assertEquals("021", MultithreadTemplate.toText(charSet, i++));
    assertEquals("121", MultithreadTemplate.toText(charSet, i++));
    assertEquals("221", MultithreadTemplate.toText(charSet, i++));
    assertEquals("002", MultithreadTemplate.toText(charSet, i++));
    assertEquals("102", MultithreadTemplate.toText(charSet, i++));
    assertEquals("202", MultithreadTemplate.toText(charSet, i++));
    assertEquals("012", MultithreadTemplate.toText(charSet, i++));
    assertEquals("112", MultithreadTemplate.toText(charSet, i++));
    assertEquals("212", MultithreadTemplate.toText(charSet, i++));
    assertEquals("022", MultithreadTemplate.toText(charSet, i++));
    assertEquals("122", MultithreadTemplate.toText(charSet, i++));
    assertEquals("222", MultithreadTemplate.toText(charSet, i++));
//    assertEquals("0000", MultithreadTemplate.toText(charSet, i++));
    assertEquals("0001", MultithreadTemplate.toText(charSet, i++));
  }

  @Test
  void testEncrypt() throws GeneralSecurityException {
    assertEquals("dI5r7aoODMRkgH5qX6oTAA==", encrypt("key01", "plain001"));
  }

  @Test
  void testDecrypt() throws GeneralSecurityException {
    assertEquals("plain001", decrypt("key01", "dI5r7aoODMRkgH5qX6oTAA=="));
  }

  private static String encrypt(String key, String input) throws GeneralSecurityException {
    byte[] encrypted = encryptBytes(key, toBytes(input));
    return Base64.encodeBase64String(encrypted);
  }

  private static String decrypt(String key, String input) throws GeneralSecurityException {
    byte[] decrypted = decryptBytes(key, Base64.decodeBase64(input));
    return new String(decrypted);
  }

  private static byte[] encryptBytes(String key, byte[] input) throws GeneralSecurityException {
    Cipher cipher = setupCipher(Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(input);
  }

  private static byte[] decryptBytes(String key, byte[] input) throws GeneralSecurityException {
    Cipher cipher = setupCipher(Cipher.DECRYPT_MODE, key);
    return cipher.doFinal(input);
  }

  private static Cipher setupCipher(int mode, String key) throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance("Blowfish");
    cipher.init(mode, new SecretKeySpec(toBytes(key), "Blowfish"));
    return cipher;
  }

  private static byte[] toBytes(String str) {
    try {
      return str.getBytes("UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new IllegalStateException(e);
    }
  }
}
