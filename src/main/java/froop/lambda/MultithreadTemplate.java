package froop.lambda;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class MultithreadTemplate {
  private final CipherCondition condition;
  private final long start;
  private final int poolSize;
  private final int capacity;

  public MultithreadTemplate(CipherCondition condition, int capacity, long start) {
    this.condition = condition;
    this.capacity = capacity;
    this.start = start;
    this.poolSize = Runtime.getRuntime().availableProcessors();
    System.out.println("poolSize: " + poolSize);
  }

  public String execute() throws GeneralSecurityException {
    final List<Future<String>> futures = new ArrayList<>();
    final ExecutorService executor = Executors.newFixedThreadPool(poolSize);
    final int threadCapBase = capacity / poolSize;

    long next = start;
    for (int i = 0; i < poolSize; i++) {
      int remainder = i < (capacity % poolSize) ? 1 : 0;
      int threadCap = threadCapBase + remainder;
      HeavyTask task = new HeavyTask(condition, threadCap, next);
      futures.add(executor.submit(task));
      next += threadCap;
    }

    try {
      for (Future<String> future : futures) {
        String res = future.get();
        if (res.length() > 0) {
          return res;
        }
      }
      return "";
    } catch (InterruptedException | ExecutionException e) {
      throw new RuntimeException(e);
    } finally {
      executor.shutdownNow();
    }
  }

  public static class CipherCondition {
    private final String algorithm;
    private final String keyCharSet;
    private final String plainText;
    private final byte[] encrypted;

    public CipherCondition(String algorithm, String keyCharSet, String plainText, byte[] encrypted) {
      this.algorithm = algorithm;
      this.keyCharSet = keyCharSet;
      this.plainText = plainText;
      this.encrypted = encrypted;
    }
  }

  private static class HeavyTask implements Callable<String> {
    private final Cipher cipher;
    private final CipherCondition condition;
    private final int capacity;
    private final long start;

    public HeavyTask(CipherCondition condition, int capacity, long start) throws GeneralSecurityException {
      this.condition = condition;
      this.capacity = capacity;
      this.start = start;
      this.cipher = Cipher.getInstance(condition.algorithm);
    }

    @Override
    public String call() throws GeneralSecurityException, InterruptedException {
      System.out.println(String.format("%s: capacity=%d start=%d", Thread.currentThread().getName(), capacity, start));
      for (long counter = start; counter <= start + capacity; counter++) {
        if (Thread.interrupted()) {
          throw new InterruptedException();
        }
        String key = toText(condition.keyCharSet, counter);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(toBytes(key), condition.algorithm));
        byte[] encrypted = cipher.doFinal(toBytes(condition.plainText));
        if (Arrays.equals(encrypted, condition.encrypted)) {
          return key;
        }
      }
      return "";
    }

    private static String toText(String charSet, long index) {
      StringBuilder keyBuilder = new StringBuilder();
      long next = index;
      while (next > 0) {
        int remainder = (int)(next % charSet.length());
        keyBuilder.append(charSet.charAt(remainder));
        next /= charSet.length();
      }
      return keyBuilder.toString();
    }

    private static byte[] toBytes(String str) {
      try {
        return str.getBytes("UTF-8");
      } catch (UnsupportedEncodingException e) {
        throw new IllegalStateException(e);
      }
    }
  }
}
