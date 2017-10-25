package research.crypto.main.tests;

import java.security.SecureRandom;
import junit.framework.TestCase;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import research.crypto.main.BlockCipher;
import research.crypto.main.BlockCipherAlgorithms;
import research.crypto.main.CipherException;

/**
 * 
 * @author Alejandro Aguilera Vega
 *
 */
public class BlockCipherTest extends TestCase {

	public BlockCipherTest(String name){
		super(name);
	}

	public void test3DESAlgorithms() throws CipherException, DecoderException{

		byte[] k = new byte[BlockCipherAlgorithms.DESede_GENERAL_INFO.getKeyLength()];
		byte[] iv = new byte[BlockCipherAlgorithms.DESede_GENERAL_INFO.getInitialVectorLength()];
		SecureRandom R = new SecureRandom();
		R.nextBytes(k);
		R.nextBytes(iv);
		String message = null;

		System.out.println();System.out.println(
		"***************************************************************************** \r\n" +
		"* SAMPLE: BlockCipherAlgorithms.DESede_ECB_NoPadding BYTE ARRAYS            * \r\n" +
		"*****************************************************************************");
		message = "0123456789ABCDEF0123456789ABCDEF";
		BlockCipher B = new BlockCipher(BlockCipherAlgorithms.DESede_ECB_NoPadding);
		byte[] encryptedBytes = B.encrypt(k, message.getBytes());
		System.out.println("DESede_ECB_NoPadding encryptedMsg: "+Hex.encodeHexString(encryptedBytes));

		byte[] decryptedBytes = B.decrypt(k, encryptedBytes);
		System.out.println("DESede_ECB_NoPadding decryptedMsg: "+(new String(decryptedBytes)));
		assertEquals(message,(new String(decryptedBytes)));

		System.out.println();System.out.println(
		"***************************************************************************** \r\n" +
		"* SAMPLE: BlockCipherAlgorithms.DESede_ECB_PKCS5Padding BYTE ARRAYS         * \r\n" +
		"*****************************************************************************");
		message = "0123456789ABCDEF0123456789ABCDEF012345";
		B = new BlockCipher(BlockCipherAlgorithms.DESede_ECB_PKCS5Padding);
		encryptedBytes = B.encrypt(k, message.getBytes());
		System.out.println("DESede_ECB_PKCS5Padding encryptedMsg: "+Hex.encodeHexString(encryptedBytes));

		decryptedBytes = B.decrypt(k, encryptedBytes);
		System.out.println("DESede_ECB_PKCS5Padding decryptedMsg: "+(new String(decryptedBytes)));
		assertEquals(message,(new String(decryptedBytes)));

		System.out.println();System.out.println(
		"***************************************************************************** \r\n" +
		"* SAMPLE: BlockCipherAlgorithms.DESede_CBC_NoPadding BYTE ARRAYS            * \r\n" +
		"*****************************************************************************");
		message = "0123456789ABCDEF0123456789ABCDEF";
		B = new BlockCipher(BlockCipherAlgorithms.DESede_CBC_NoPadding, iv);
		encryptedBytes = B.encrypt(k, message.getBytes());
		System.out.println("DESede_CBC_NoPadding encryptedMsg: "+Hex.encodeHexString(encryptedBytes));

		decryptedBytes = B.decrypt(k, encryptedBytes);
		System.out.println("DESede_CBC_NoPadding decryptedMsg: "+(new String(decryptedBytes)));
		assertEquals(message,(new String(decryptedBytes)));

		System.out.println();System.out.println(
		"***************************************************************************** \r\n" +
		"* SAMPLE: BlockCipherAlgorithms.DESede_CBC_PKCS5Padding BYTE ARRAYS         * \r\n" +
		"*****************************************************************************");
		message = "0123456789ABCDEF0123456789ABCDEF012345";
		B = new BlockCipher(BlockCipherAlgorithms.DESede_CBC_PKCS5Padding, iv);
		encryptedBytes = B.encrypt(k, message.getBytes());
		System.out.println("DESede_CBC_PKCS5Padding encryptedMsg: "+Hex.encodeHexString(encryptedBytes));

		decryptedBytes = B.decrypt(k, encryptedBytes);
		System.out.println("DESede_CBC_PKCS5Padding decryptedMsg: "+(new String(decryptedBytes)));
		assertEquals(message,(new String(decryptedBytes)));

		System.out.println();System.out.println(
		"***************************************************************************** \r\n" +
		"* SAMPLE: BlockCipher.DESede_ECB_NoPadding HEX STRINGS                      * \r\n" +
		"*****************************************************************************");
		//Hex equivalent to: 0123456789ABCDEF0123456789ABCDEF (considering ASCII values)
		message = "3031323334353637383941424344454630313233343536373839414243444546";
		B = new BlockCipher(BlockCipherAlgorithms.DESede_ECB_NoPadding);
		String strEncryptedBytes = B.encrypt(Hex.encodeHexString(k), message);
		System.out.println("DESede_ECB_NoPadding hexStrEncrypted: "+strEncryptedBytes);

		String strDecryptedBytes = B.decrypt(Hex.encodeHexString(k), strEncryptedBytes);
		System.out.println("DESede_ECB_NoPadding hexStrDecrypted: "+strDecryptedBytes);
		System.out.println("DESede_ECB_NoPadding hexStrDecoded: "+(new String(Hex.decodeHex(strDecryptedBytes.toCharArray()))));
		assertEquals(message, strDecryptedBytes);

		System.out.println();System.out.println(
		"***************************************************************************** \r\n" +
		"* SAMPLE: BlockCipher.DESede_ECB_PKCS5Padding HEX STRINGS                   * \r\n" +
		"*****************************************************************************");
		//Hex equivalent to: 0123456789ABCDEF0123456789ABCDEF (considering ASCII values)
		message = "3031323334353637383941424344454630313233343536373839414243444546";
		B = new BlockCipher(BlockCipherAlgorithms.DESede_ECB_PKCS5Padding);
		strEncryptedBytes = B.encrypt(Hex.encodeHexString(k), message);
		System.out.println("DESede_ECB_PKCS5Padding hexStrEncrypted: "+strEncryptedBytes);

		strDecryptedBytes = B.decrypt(Hex.encodeHexString(k), strEncryptedBytes);
		System.out.println("DESede_ECB_PKCS5Padding hexStrDecrypted: "+strDecryptedBytes);
		System.out.println("DESede_ECB_PKCS5Padding hexStrDecoded: "+(new String(Hex.decodeHex(strDecryptedBytes.toCharArray()))));
		assertEquals(message, strDecryptedBytes);

		System.out.println();System.out.println(
		"***************************************************************************** \r\n" +
		"* SAMPLE: BlockCipher.DESede_CBC_NoPadding HEX STRINGS                      * \r\n" +
		"*****************************************************************************");
		//Hex equivalent to: 0123456789ABCDEF0123456789ABCDEF (considering ASCII values)
		message = "3031323334353637383941424344454630313233343536373839414243444546";
		B = new BlockCipher(BlockCipherAlgorithms.DESede_CBC_NoPadding, iv);
		strEncryptedBytes = B.encrypt(Hex.encodeHexString(k), message);
		System.out.println("DESede_CBC_NoPadding hexStrEncrypted: "+strEncryptedBytes);

		strDecryptedBytes = B.decrypt(Hex.encodeHexString(k), strEncryptedBytes);
		System.out.println("DESede_CBC_NoPadding hexStrDecrypted: "+strDecryptedBytes);
		System.out.println("DESede_CBC_NoPadding hexStrDecoded: "+(new String(Hex.decodeHex(strDecryptedBytes.toCharArray()))));
		assertEquals(message, strDecryptedBytes);

		System.out.println();System.out.println(
		"***************************************************************************** \r\n" +
		"* SAMPLE: BlockCipher.DESede_CBC_PKCS5Padding HEX STRINGS                   * \r\n" +
		"*****************************************************************************");
		//Hex equivalent to: 0123456789ABCDEF0123456789ABCDEF (considering ASCII values)
		message = "3031323334353637383941424344454630313233343536373839414243444546";
		B = new BlockCipher(BlockCipherAlgorithms.DESede_CBC_PKCS5Padding, iv);
		strEncryptedBytes = B.encrypt(Hex.encodeHexString(k), message);
		System.out.println("DESede_CBC_PKCS5Padding hexStrEncrypted: "+strEncryptedBytes);
		strDecryptedBytes = B.decrypt(Hex.encodeHexString(k), strEncryptedBytes);
		System.out.println("DESede_CBC_PKCS5Padding hexStrDecrypted: "+strDecryptedBytes);
		System.out.println("DESede_CBC_PKCS5Padding hexStrDecoded: "+(new String(Hex.decodeHex(strDecryptedBytes.toCharArray()))));
		assertEquals(message, strDecryptedBytes);
		System.out.println();
	}

	public void testAESAlgorithms() throws CipherException, DecoderException{

		byte[] k_aes = new byte[BlockCipherAlgorithms.AES_GENERAL_INFO.getKeyLength()];
		byte[] iv_aes = new byte[BlockCipherAlgorithms.AES_GENERAL_INFO.getInitialVectorLength()];
		SecureRandom R = new SecureRandom();
		R.nextBytes(k_aes);
		R.nextBytes(iv_aes);
		String message = null;

		System.out.println();System.out.println(
		"***************************************************************************** \r\n" +
		"* SAMPLE: BlockCipher.AES_EBC_NoPadding BYTE ARRAYS                         * \r\n" +
		"*****************************************************************************");
		message = "0123456789ABCDEF0123456789ABCDEF";
		BlockCipher B = new BlockCipher(BlockCipherAlgorithms.AES_ECB_NoPadding);
		byte[] encryptedBytes = B.encrypt(k_aes, message.getBytes());
		System.out.println("AES_EBC_NoPadding encryptedMsg: "+Hex.encodeHexString(encryptedBytes));

		byte[] decryptedBytes = B.decrypt(k_aes, encryptedBytes);
		System.out.println("AES_EBC_NoPadding decryptedMsg: "+(new String(decryptedBytes)));
		assertEquals(message,(new String(decryptedBytes)));

		System.out.println();System.out.println(
		"***************************************************************************** \r\n" +
		"* SAMPLE: BlockCipher.AES_ECB_PKCS5Padding BYTE ARRAYS                      * \r\n" +
		"*****************************************************************************");
		message = "0123456789ABCDEF0123456789ABCDEF012345";
		B = new BlockCipher(BlockCipherAlgorithms.AES_ECB_PKCS5Padding);
		encryptedBytes = B.encrypt(k_aes, message.getBytes());
		System.out.println("AES_ECB_PKCS5Padding encryptedMsg: "+Hex.encodeHexString(encryptedBytes));

		decryptedBytes = B.decrypt(k_aes, encryptedBytes);
		System.out.println("AES_ECB_PKCS5Padding decryptedMsg: "+(new String(decryptedBytes)));
		assertEquals(message,(new String(decryptedBytes)));

		System.out.println();System.out.println(
		"***************************************************************************** \r\n" +
		"* SAMPLE: BlockCipher.AES_CBC_NoPadding BYTE ARRAYS                         * \r\n" +
		"*****************************************************************************");
		message = "0123456789ABCDEF0123456789ABCDEF";
		B = new BlockCipher(BlockCipherAlgorithms.AES_CBC_NoPadding, iv_aes);
		encryptedBytes = B.encrypt(k_aes, message.getBytes());
		System.out.println("AES_CBC_NoPadding encryptedMsg: "+Hex.encodeHexString(encryptedBytes));

		decryptedBytes = B.decrypt(k_aes, encryptedBytes);
		System.out.println("AES_CBC_NoPadding decryptedMsg: "+(new String(decryptedBytes)));
		assertEquals(message,(new String(decryptedBytes)));

		System.out.println();System.out.println(
		"***************************************************************************** \r\n" +
		"* SAMPLE: BlockCipher.AES_CBC_PKCS5Padding BYTE ARRAYS                         * \r\n" +
		"*****************************************************************************");
		message = "0123456789ABCDEF0123456789ABCDEF012345";
		B = new BlockCipher(BlockCipherAlgorithms.AES_CBC_PKCS5Padding, iv_aes);
		encryptedBytes = B.encrypt(k_aes, message.getBytes());
		System.out.println("AES_CBC_PKCS5Padding encryptedMsg: "+Hex.encodeHexString(encryptedBytes));

		decryptedBytes = B.decrypt(k_aes, encryptedBytes);
		System.out.println("AES_CBC_PKCS5Padding decryptedMsg: "+(new String(decryptedBytes)));
		assertEquals(message,(new String(decryptedBytes)));
		System.out.println();
	}
}
