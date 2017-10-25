package research.crypto.main.tests;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.ArrayList;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import junit.framework.TestCase;

/**
 * 
 * @author Alejandro Aguilera Vega
 * 
 */
public class SecureCredentialsTest extends TestCase {

	public SecureCredentialsTest(String name) {
		super(name);
	}

	public void testKeyDerivation() throws CipherException, DecoderException,
			UnsupportedEncodingException {

		System.out.println();
		for (int i = 0; i < 100; i++) {

			SecureRandom R = new SecureRandom();
			byte[] key = new byte[BlockCipherAlgorithms.AES_GENERAL_INFO
					.getKeyLength()];
			R.nextBytes(key);
			String noise = "";

			/**
			 * Creating Derived Key
			 */
			SecureCredentials M = new SecureCredentials(
					"reallyLongPasswordLikeTheOnesEverybodyShouldBeUsinByNow"
							+ i, Hex.encodeHexString(key), 16384, 4, 1);
			String encDk = M.getEncryptedDerivedKey();
			String encSalt = M.getEncryptedSaltAsHexStr();
			String iv = M.getInitialVectorAsHexStr();

			System.out.println("key: " + Hex.encodeHexString(key));
			System.out.println("encDk: " + encDk);
			System.out.println("encSalt: " + encSalt);
			System.out.println("iv: " + iv);

			/**
			 * Validating Derived Key
			 */
			if (i >= 75) {
				noise = "noise" + i;
			}

			M = new SecureCredentials(
					"reallyLongPasswordLikeTheOnesEverybodyShouldBeUsinByNow"
							+ i + noise, Hex.encodeHexString(key), encDk,
					encSalt, iv, 16384, 4, 1);
			System.out.println(M.validateCredentials());
		}
	}

	public void testKeyDerivationThreadSafety() {

		long start = System.currentTimeMillis();

		ArrayList<SynchronizedThread> sibblings = new ArrayList<SynchronizedThread>();
		int max = 100;
		int iterations = 100;

		for (int i = 0; i < max; i++) {

			String noise = "";
			if (i >= 60) {
				noise = "noise" + String.valueOf(i);
			} else {
				noise = "";
			}

			SynchronizedThread T = new SynchronizedThread(iterations,
					String.valueOf(i), noise);
			sibblings.add(T);
		}

		for (int i = 0; i < max; i++) {
			sibblings.get(i).start();
		}

		System.out.println();
		boolean allFinished = false;
		int c = 0, d = 0;
		String[] sandClock = {"\r-","\r\\","\r|","\r/"};
		while (!allFinished) {
			allFinished = true;
			for (int i = 0; i < sibblings.size(); i++) {
				allFinished = (allFinished && sibblings.get(i).isFinished());
			}
			if (c % 20 == 0){
				System.out.print(sandClock[d]);
				d++;
				if (d == sandClock.length){
					d=0;
				}
			}
		}System.out.println();

		int countTrue = 0;
		int countFalse = 0;
		for (int i = 0; i < sibblings.size(); i++) {
			if (sibblings.get(i).isResult()) {
				countTrue++;
			} else {
				countFalse++;
			}
		}

		System.out.println("countTrue:" + countTrue);
		System.out.println("countFalse:" + countFalse);
		long total = System.currentTimeMillis() - start;
		System.out.println("total time: " + total);
	}
}
