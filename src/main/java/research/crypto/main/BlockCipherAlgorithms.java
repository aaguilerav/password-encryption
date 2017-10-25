package research.crypto.main;

/**
 * Lists all the different types of ciphers that can
 * be used in the BlockCipher class (3DES and AES-256)
 * 
 * IMPORTANT: Java Cryptography Extension (JCE) Unlimited 
 * Strength Jurisdiction Policy should be installed on the machine 
 * that is using this library.
 * 
 * @author Alejandro Aguilera Vega
 *
 */
public enum BlockCipherAlgorithms {

	/**
	 * 						 Algo,KeySize,BlockOperation,         Requires IV, IV size, Key Derivation Function (not used yet)
	 */
	DESede_CBC_NoPadding(	"DESede",24,"DESede/CBC/NoPadding"		,true		,8		,"PBKDF2WithHmacSHA1"),
	DESede_CBC_PKCS5Padding("DESede",24,"DESede/CBC/PKCS5Padding"	,true		,8		,"PBKDF2WithHmacSHA1"),
	DESede_ECB_NoPadding(	"DESede",24,"DESede/ECB/NoPadding"		,false		,8		,"PBKDF2WithHmacSHA1"),
	DESede_ECB_PKCS5Padding("DESede",24,"DESede/ECB/PKCS5Padding"	,false		,8		,"PBKDF2WithHmacSHA1"),
	DESede_GENERAL_INFO(	"DESede",24,null						,false		,8		,null),

	AES_CBC_NoPadding(		"AES"	,32,"AES/CBC/NoPadding"			,true		,16		,"PBKDF2WithHmacSHA1"),
	AES_CBC_PKCS5Padding(	"AES"	,32,"AES/CBC/PKCS5Padding"		,true		,16		,"PBKDF2WithHmacSHA1"),
	AES_ECB_NoPadding(		"AES"	,32,"AES/ECB/NoPadding"			,false		,16		,"PBKDF2WithHmacSHA1"),
	AES_ECB_PKCS5Padding(	"AES"	,32,"AES/ECB/PKCS5Padding"		,false		,16		,"PBKDF2WithHmacSHA1"),
	AES_GENERAL_INFO(		"AES"	,32,null						,false		,16		,null);

	/**
	 * The Block cipher algorithm
	 */
	private String algorithm;

	/**
	 * The required key size for the corresponding cipher algorithm
	 */
	private int keyLength;

	/**
	 * The type of block operation
	 */
	private String fullDescription;

	/**
	 * Determines if an Initial Vector is required
	 */
	private boolean requiresInitialVector;

	/**
	 * The required initial vector size for the 
	 * corresponding cipher algorithm
	 */
	private int initialVectorLength;
	
	/**
	 * 
	 */
	private String keyDerivationFunction;

	/**
	 * Constructor
	 * @param algorithm
	 * @param fullDescription
	 */
	BlockCipherAlgorithms(
			final String algorithm, 
			final int keyLength, 
			final String fullDescription,
			final boolean requiresInitialVector,
			final int initialVectorLength,
			final String keyDerivationFunction){
		this.algorithm = algorithm;
		this.keyLength = keyLength;
		this.fullDescription = fullDescription;
		this.requiresInitialVector = requiresInitialVector;
		this.initialVectorLength = initialVectorLength;
		this.keyDerivationFunction = keyDerivationFunction;
	}

	public String getAlgorithm(){
		return this.algorithm;
	}

	public int getKeyLength(){
		return this.keyLength;
	}
	
	public int getKeyLengthInBits(){
		return 8*this.keyLength;
	}

	public String getFullDescription(){
		return this.fullDescription;
	}

	public boolean isRequiresInitialVector(){
		return this.requiresInitialVector;
	}

	public int getInitialVectorLength(){
		return this.initialVectorLength;
	}
	
	public int getInitialVectorLengthInBits(){
		return 8*this.initialVectorLength;
	}
	
	public String getKeyDerivationFunction(){
		return this.keyDerivationFunction;
	}
}
