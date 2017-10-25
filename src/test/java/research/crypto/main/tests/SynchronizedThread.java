package research.crypto.main.tests;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import research.crypto.main.BlockCipherAlgorithms;
import research.crypto.main.CipherException;
import research.crypto.main.SecureCredentials;

public class SynchronizedThread extends Thread {

	private boolean result = true;
	private String noise;
	private String index;
	
	public boolean isResult() {
		return result;
	}

	private int iterations;
	private boolean finished = false;

	public boolean isFinished() {
		return finished;
	}

	public SynchronizedThread(
			int iterations,
			String index,
			String noise)
	{
		this.iterations = iterations;
		this.index = index;
		this.noise = noise;
	}

	public void run() {

		System.out.println("Sibling is created. Reporting: " + this.index);

		for (int i=0; i<this.iterations; i++){
			
			SecureRandom R = new SecureRandom();
			byte[] key = new byte[BlockCipherAlgorithms.AES_GENERAL_INFO.getKeyLength()];
			R.nextBytes(key);

			/**
			 * Creating Derived Key
			 */
			SecureCredentials M;
			try {
				M = new SecureCredentials(
						this.index+"reallyLongPasswordLikeTheOnesEverybodyShouldBeUsinByNow"+i,
						Hex.encodeHexString(key),
						4096,2,1);

				String encDk = M.getEncryptedDerivedKey();
				String encSalt = M.getEncryptedSaltAsHexStr();
				String iv = M.getInitialVectorAsHexStr();

				M = new SecureCredentials(
						this.index+"reallyLongPasswordLikeTheOnesEverybodyShouldBeUsinByNow"+i+this.noise,
						Hex.encodeHexString(key),
						encDk,
						encSalt,
						iv,
						4096,2,1);

				this.result = (this.result && M.validateCredentials());

			} catch (CipherException e) {
				e.printStackTrace();
			} catch (DecoderException e) {
				e.printStackTrace();
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		}
		this.finished = true;
	}
}
