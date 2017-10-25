package research.crypto.main;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

/**
 * Block Cipher implementation for 3DES and AES-256.
 * 
 * @author Alejandro Aguilera Vega
 * @date Sep-19-2016
 * @company BANKAOOL
 */
public class BlockCipher {

	/**
	 * Logger that sends information to centralized logs
	 */
	private static final Logger LOG
			= Logger.getLogger(BlockCipher.class);

	/**
	 * The type of block cipher that will be used (any of the following):
	 * 		DESede/CBC/NoPadding 
	 * 		DESede/CBC/PKCS5Padding 
	 * 		DESede/ECB/NoPadding 
	 * 		DESede/ECB/PKCS5Padding 
	 * 		AES/CBC/NoPadding 
	 * 		AES/CBC/PKCS5Padding 
	 * 		AES/ECB/NoPadding 
	 * 		AES/ECB/PKCS5Padding
	 */
	private BlockCipherAlgorithms cipherType;

	/**
	 * If applies, the 8 bytes or 16 bytes initial vector.
	 */
	private byte[] initialVector = null;

	/**
	 * Initializes BlockCipher with the type of cipher that is going to be used
	 * @param cipherType
	 * @throws CipherException
	 */
	public BlockCipher(final BlockCipherAlgorithms cipherType) 
			throws CipherException {

		this.validateInputParameter(cipherType, "cipherType");

		this.cipherType = cipherType;
		if (this.cipherType.isRequiresInitialVector()){
			throw new CipherException(CipherExceptionCauses.InitialVectorNeeded);
		}

		if (LOG.isDebugEnabled()){
			LOG.debug("BlockCipher created with algorithm: " + 
					this.cipherType.getFullDescription());
		}
	}

	/**
	 * Initializes BlockCipher with the type of cipher that is going to be used
	 * and the corresponding initial vector if needed
	 * @param cipherType
	 * @param iv
	 * @throws CipherException
	 */
	public BlockCipher(final BlockCipherAlgorithms cipherType, final byte[] iv) 
			throws CipherException {

		this.validateInputParameter(cipherType, "cipherType");
		this.validateInputParameter(iv, "iv");

		this.initialVector = iv;
		this.cipherType = cipherType;

		/**
		 * If the type of cipher doesn't require an initial vector, and exception is thrown
		 */
		if (!this.cipherType.isRequiresInitialVector()){
			throw new CipherException(CipherExceptionCauses.InitialVectorNotNecessary);
		}

		/**
		 * If the initial vector is not the expected size or is null, 
		 * and exception is thrown
		 */
		if (this.cipherType.isRequiresInitialVector()
				&& !this.validateInitialVector()){
			throw new CipherException(CipherExceptionCauses.InvalidInitialVector);
		}

		if (LOG.isDebugEnabled()){
			LOG.debug("BlockCipher created with algorithm: " + 
					this.cipherType.getFullDescription());
		}
	}

	/**
	 * Initializes BlockCipher with the type of cipher that is going to be used
	 * and the corresponding initial vector if needed
	 * @param cipherType
	 * @param ivAsHexString
	 * @throws CipherException
	 */
	public BlockCipher(final BlockCipherAlgorithms cipherType, final String ivAsHexString) 
			throws CipherException {

		this.validateInputParameter(cipherType, "cipherType");
		this.validateInputParameter(ivAsHexString, "ivAsHexString");

		this.cipherType = cipherType;
		try{
			this.initialVector = Hex.decodeHex(
					ivAsHexString.toCharArray());
		}catch(DecoderException ex){
			throw new CipherException(ex, CipherExceptionCauses.DecoderError);
		}

		/**
		 * If the type of cipher doesn't require an initial vector, and exception is thrown.
		 */
		if (!this.cipherType.isRequiresInitialVector()){
			throw new CipherException(CipherExceptionCauses.InitialVectorNotNecessary);
		}

		/**
		 * If the initial vector is not the expected size or is null, 
		 * and exception is thrown
		 */
		if (this.cipherType.isRequiresInitialVector()
				&& !this.validateInitialVector()){
			throw new CipherException(CipherExceptionCauses.InvalidInitialVector);
		}

		if (LOG.isDebugEnabled()){
			LOG.debug("BlockCipher created with algorithm: " + 
					this.cipherType.getFullDescription());
		}
	}

	/**
	 * Encrypts messageAsHexString using keyAsHexString as key
	 * messageAsHexString and keyAsHexString are decoded from 
	 * HexStrings into byte arrays
	 * @param keyAsHexString
	 * @param messageAsHexString
	 * @throws CipherException
	 * @return Encrypted message as HexString
	 */
	public String encrypt(final String keyAsHexString, final String messageAsHexString) 
			throws 	CipherException {

		this.validateInputParameter(messageAsHexString, "messageAsHexString");
		final byte[] key = this.validateStringInputKey(keyAsHexString);
		if (key == null) {
			throw new CipherException(CipherExceptionCauses.InvalidKey);
		}

		byte[] messageBytes = null;
		try {
			messageBytes = Hex.decodeHex(messageAsHexString.toCharArray());
		} catch (DecoderException e) {
			throw new CipherException(e, CipherExceptionCauses.DecoderError);
		}
		final byte[] result = this.encrypt(key, messageBytes);
		return Hex.encodeHexString(result);
	}

	/**
	 * Encrypts m using k as key
	 * @param k
	 * @param m
	 * @throws CipherException
	 * @return 
	 */
	public byte[] encrypt(final byte[] k, final byte[] m) 
			throws 	CipherException {

		this.validateInputParameter(m, "m");
		final byte[] inputKey = this.validateBytesInputKey(k);
		if (inputKey == null) {
			throw new CipherException(CipherExceptionCauses.InvalidKey);
		}

		byte[] result = null;
		try {
			final SecretKey key = new SecretKeySpec(inputKey, this.cipherType.getAlgorithm());
			final Cipher cipher = Cipher.getInstance(this.cipherType.getFullDescription());
			if (this.cipherType.isRequiresInitialVector()){
				cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(this.initialVector));
			}else{
				cipher.init(Cipher.ENCRYPT_MODE, key);
			}
			result = cipher.doFinal(m);
		} catch (InvalidKeyException e) {
			throw new CipherException(e, CipherExceptionCauses.InvalidKey);
		} catch (NoSuchAlgorithmException e) {
			throw new CipherException(e, CipherExceptionCauses.NoSuchAlgorithm);
		} catch (NoSuchPaddingException e) {
			throw new CipherException(e, CipherExceptionCauses.NoSuchPadding);
		} catch (IllegalBlockSizeException e) {
			throw new CipherException(e, CipherExceptionCauses.IllegalBlockSize);
		} catch (BadPaddingException e) {
			throw new CipherException(e, CipherExceptionCauses.BadPadding);
		} catch (InvalidAlgorithmParameterException e) {
			throw new CipherException(e, CipherExceptionCauses.InvalidAlgorithmParameter);
		}
		return result;
	}

	/**
	 * Decrypts messageAsHexString using keyAsHexString as key
	 * messageAsHexString and keyAsHexString are decoded from 
	 * HexStrings into byte arrays
	 * @param keyAsHexString
	 * @param messageAsHexString
	 * @throws CipherException
	 * @return 
	 */
	public String decrypt(final String keyAsHexString, final String messageAsHexString) 
			throws 	CipherException {

		this.validateInputParameter(messageAsHexString, "messageAsHexString");
		final byte[] key = this.validateStringInputKey(keyAsHexString);
		if (key == null) {
			throw new CipherException(CipherExceptionCauses.InvalidKey);
		}

		byte[] messageBytes;
		try {
			messageBytes = Hex.decodeHex(messageAsHexString.toCharArray());
		} catch (DecoderException e) {
			throw new CipherException(e, CipherExceptionCauses.DecoderError);
		}
		final byte[] result = this.decrypt(key, messageBytes);
		return Hex.encodeHexString(result);
	}

	/**
	 * Decrypts m using k as key
	 * @param k
	 * @param m
	 * @throws CipherException
	 * @return 
	 */
	public byte[] decrypt(final byte[] k, final byte[] m) 
			throws 	CipherException {

		this.validateInputParameter(m, "m");
		final byte[] inputKey = this.validateBytesInputKey(k);
		if (inputKey == null) {
			throw new CipherException(CipherExceptionCauses.InvalidKey);
		}

		byte[] result = null;
		try{
			final SecretKey key = new SecretKeySpec(inputKey, this.cipherType.getAlgorithm());
			final Cipher decipher = Cipher.getInstance(this.cipherType.getFullDescription());
			if (this.cipherType.isRequiresInitialVector()){
				decipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(this.initialVector));
			}else{
				decipher.init(Cipher.DECRYPT_MODE, key);
			}
			result = decipher.doFinal(m);
		} catch (InvalidKeyException e) {
			throw new CipherException(e, CipherExceptionCauses.InvalidKey);
		} catch (NoSuchAlgorithmException e) {
			throw new CipherException(e, CipherExceptionCauses.NoSuchAlgorithm);
		} catch (NoSuchPaddingException e) {
			throw new CipherException(e, CipherExceptionCauses.NoSuchPadding);
		} catch (IllegalBlockSizeException e) {
			throw new CipherException(e, CipherExceptionCauses.IllegalBlockSize);
		} catch (BadPaddingException e) {
			throw new CipherException(e, CipherExceptionCauses.BadPadding);
		} catch (InvalidAlgorithmParameterException e) {
			throw new CipherException(e, CipherExceptionCauses.InvalidAlgorithmParameter);
		}
		return result;
	}

	/**
	 * Validates the length of the key that was provided
	 * @param inputKey
	 * @return
	 */
	private byte[] validateBytesInputKey(final byte[] inputKey) {

		byte[] result = null;
		if (inputKey != null) {
			if (inputKey.length == this.cipherType.getKeyLength()) {
				result = inputKey;
			}
		}
		return result;
	}

	/**
	 * Validates the length of the key that was provided
	 * @param inputKey
	 * @return
	 */
	private byte[] validateStringInputKey(final String inputKey) {

		byte[] result = null;
		if (inputKey != null) {
			try {
				byte[] inputKeyBytes = Hex.decodeHex(inputKey.toCharArray());
				if (inputKeyBytes.length == this.cipherType.getKeyLength()) {
					result = inputKeyBytes;
				} 
			} catch (DecoderException ex) {
				result = null;
			}
		}
		return result;
	}

	/**
	 * Validates the length of the initial vector that was provided
	 * @return
	 */
	private boolean validateInitialVector(){

		boolean result = false;
		if (this.initialVector != null) {
			if (this.initialVector.length == this.cipherType.getInitialVectorLength()) {
				result = true;
			}
		}
		return result;
	}

	/**
	 * Validates if an input parameter is null. If True, an exception is thrown.
	 * @param obj
	 * @param paramName
	 * @throws CipherException
	 */
	private void validateInputParameter(Object obj, String paramName) 
			throws CipherException{

		if (obj == null){
			throw new CipherException(
					CipherExceptionCauses.InvalidNullInput, 
					"Parameter: "+paramName+".");
		}
	}
}
