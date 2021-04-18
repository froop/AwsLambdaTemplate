package froop.lambda;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;

import froop.lambda.MultithreadTemplate.CipherCondition;

public class RequestHandlerTemplate implements RequestHandler<Map<String, Object>, Map<String, Object>> {

  @Override
  public Map<String, Object> handleRequest(Map<String, Object> input, Context context) {
    String algorithm = (String) input.get("algorithm");
    String keyCharSet = (String) input.get("keyCharSet");
    String plainText = (String) input.get("plainText");
    String cipherText = (String) input.get("cipherText");
    int capacity = Integer.valueOf(input.get("capacity").toString());
    long start = Long.valueOf(input.get("start").toString());

    try {
      byte[] encrypted = Base64.decodeBase64(cipherText);
      CipherCondition cond = new CipherCondition(algorithm, keyCharSet, plainText, encrypted);
      String keyText = new MultithreadTemplate(cond, capacity, start).execute();

      Map<String, Object> output = new HashMap<>(input);
      output.put("keyText", keyText);
      output.put("start", start + capacity);
      output.put("lastMatching", MultithreadTemplate.toText(keyCharSet, start + capacity - 1));
      return output;

    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  public static void main(String[] args) {
    Map<String, Object> input = new HashMap<>();
    input.put("algorithm", "Blowfish");
    input.put("keyCharSet", "0123456789abcdefghijklmnopqrstuvwxyz");
    input.put("plainText", "plain001");
    input.put("cipherText", "dI5r7aoODMRkgH5qX6oTAA==");
    input.put("capacity", 1000000);
    input.put("start", 1000001);

    Map<String, Object> output = new RequestHandlerTemplate().handleRequest(input, null);

    System.out.println(output);
  }
}
