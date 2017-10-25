package research.crypto.main;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import com.lambdaworks.crypto.SCryptUtil;

/**
 * Provides the functionality necessary for handling user passwords 
 * securely
 * @author Alejandro Aguilera Vega
 *
 */
public class SecureCredentials {

    /**
     * Logger that sends information to centralized logs
     */
    private static final Logger LOG
            = Logger.getLogger(SecureCredentials.class);
    
    /**
     * The instance of BlockCipher used to encrypt/decrypt
     */
    private BlockCipher cipher;

    /**
     * AES-256-CBC with padding algorithm is selected for future integration with EFT HSM.
     */
    private BlockCipherAlgorithms cipherType = BlockCipherAlgorithms.AES_CBC_PKCS5Padding;

    /**
     * User's password
     */
    private String clientPwd;

    /**
     * The key that is used to encrypt the salt
     */
    private String keyAsHexStr;

    /**
     * The password transformed into a Derived Key using scrypt
     */
    private String derivedKey = null;

    /**
     * The salt that is used to calculate the derived key
     */
    private String saltAsHexStr;

    /**
     * The initial vector used by the cipher
     */
    private String initialVectorAsHexStr;

    /**
     * CPU cost parameter. (Default value: 16384)
     */
    private int derivedKeyAlgoMaxMemory = 16384;

    /**
     * Memory cost parameter. (Default value: 2)
     */
    private int derivedKeyAlgoMaxMemoryFraction = 2;

    /**
     * Parallelization parameter. (Default value: 1)
     */
    private int derivedKeyAlgoMaxTime = 1;


    /**
     * Constructor. This one should be used when securing user credentials.
     * @param clientPwd
     * @param keyAsHexStr
     * @param derivedKeyAlgoMaxMemory
     * @param derivedKeyAlgoMaxMemoryFraction
     * @param derivedKeyAlgoMaxTime
     * @throws DecoderException
     * @throws CipherException
     */
    public SecureCredentials(
            final String clientPwd,
            final String keyAsHexStr,
            final int derivedKeyAlgoMaxMemory,
            final int derivedKeyAlgoMaxMemoryFraction,
            final int derivedKeyAlgoMaxTime) 
            throws DecoderException, CipherException {

        this.clientPwd = clientPwd;
        this.keyAsHexStr = keyAsHexStr;
        this.saltAsHexStr = this.generateRandomSalt();
        this.initialVectorAsHexStr = this.generateRandomInitialVector();
        this.cipher = new BlockCipher(this.cipherType, this.initialVectorAsHexStr);
        this.derivedKeyAlgoMaxMemory = derivedKeyAlgoMaxMemory;
        this.derivedKeyAlgoMaxMemoryFraction = derivedKeyAlgoMaxMemoryFraction;
        this.derivedKeyAlgoMaxTime = derivedKeyAlgoMaxTime;

        LOG.info("SecureCredentials created in order to validate existing credentials.");
        if (LOG.isDebugEnabled()){
            LOG.debug("SecureCredentials created with the following parameters: \r\n"+
                    "derivedKeyAlgoMaxMemory: "+this.derivedKeyAlgoMaxMemory+"\r\n"+
                    "derivedKeyAlgoMaxMemoryFraction: "+this.derivedKeyAlgoMaxMemoryFraction+"\r\n"+
                    "derivedKeyAlgoMaxTime: "+this.derivedKeyAlgoMaxTime+"\r\n");
        }
    }

    /**
     * Constructor. This one should be used when validating user credentials.
     * @param clientPwd
     * @param keyAsHexStr
     * @param encryptedDerivedKeyAsHexStr
     * @param encryptedSaltAsHexStr
     * @param initialVectorAsHexStr
     * @param derivedKeyAlgoMaxMemory
     * @param derivedKeyAlgoMaxMemoryFraction
     * @param derivedKeyAlgoMaxTime
     * @throws DecoderException
     * @throws CipherException
     */
    public SecureCredentials(
            final String clientPwd,
            final String keyAsHexStr,
            final String encryptedDerivedKeyAsHexStr,
            final String encryptedSaltAsHexStr,
            final String initialVectorAsHexStr,
            final int derivedKeyAlgoMaxMemory,
            final int derivedKeyAlgoMaxMemoryFraction,
            final int derivedKeyAlgoMaxTime)
            throws DecoderException, CipherException{

        this.clientPwd = clientPwd;
        this.keyAsHexStr = keyAsHexStr;
        this.initialVectorAsHexStr = initialVectorAsHexStr;

        /**
         * The cipher is initialized
         */
        this.cipher = new BlockCipher(this.cipherType, this.initialVectorAsHexStr);

        /**
         * The provided derived key is decrypted.
         * ATTENTION: The derived key is a string in a specific format, its encrypted
         * form is represented as a HexString, when decrypted it must be transformed 
         * back again into a StandardCharsets.US_ASCII string so it can be properly 
         * validated.
         */
        this.derivedKey = (new String(
                Hex.decodeHex(
                    this.cipher.decrypt(
                            this.keyAsHexStr, 
                            encryptedDerivedKeyAsHexStr).toCharArray()),
                            StandardCharsets.US_ASCII));

        /**
         * The salt is decrypted.
         */
        this.saltAsHexStr = this.cipher.decrypt(this.keyAsHexStr, encryptedSaltAsHexStr);

        this.derivedKeyAlgoMaxMemory = derivedKeyAlgoMaxMemory;
        this.derivedKeyAlgoMaxMemoryFraction = derivedKeyAlgoMaxMemoryFraction;
        this.derivedKeyAlgoMaxTime = derivedKeyAlgoMaxTime;

        LOG.info("SecureCredentials created in order to register information for a new user.");
        if (LOG.isDebugEnabled()){
            LOG.debug("SecureCredentials created with the following parameters: \r\n"+
                    "derivedKeyAlgoMaxMemory: "+this.derivedKeyAlgoMaxMemory+"\r\n"+
                    "derivedKeyAlgoMaxMemoryFraction: "+this.derivedKeyAlgoMaxMemoryFraction+"\r\n"+
                    "derivedKeyAlgoMaxTime: "+this.derivedKeyAlgoMaxTime+"\r\n");
        }
    }

    /**
     * Generates a random array of bytes of the size specified by the cipher algorithm
     * @return
     */
    private String generateRandomInitialVector() {

        SecureRandom R = new SecureRandom();
        byte[] iv = new byte[this.cipherType.getInitialVectorLength()];
        R.nextBytes(iv);

        if (LOG.isDebugEnabled()){
            LOG.debug("Initial Vector generated with length: " + 
                    this.cipherType.getInitialVectorLength());
        }
        return Hex.encodeHexString(iv);
    }

    /**
     * Generates a random array of bytes of the size specified by the cipher algorithm
     * @return
     */
    private String generateRandomSalt() {

        SecureRandom R = new SecureRandom();
        byte[] salt = new byte[ 2 * this.cipherType.getKeyLength() ];
        R.nextBytes(salt);

        if (LOG.isDebugEnabled()){
            LOG.debug("Salt generated with length: " + 
                    (2 * this.cipherType.getKeyLength()));
        }
        return Hex.encodeHexString(salt);
    }

    /**
     * Validates if the derived key corresponds to 
     * the user password and the salt
     * @return
     */
    public boolean validateCredentials(){

        if (this.derivedKey == null){
            return false;
        }

        return SCryptUtil.check(
                this.saltAsHexStr + this.clientPwd, 
                this.derivedKey);
    }

    /**
     * Returns the Encrypted Derived Key calculated with the user password
     * and the salt
     * @throws CipherException 
     * @throws UnsupportedEncodingException 
     * @return
     */
    public String getEncryptedDerivedKey() 
            throws CipherException, UnsupportedEncodingException {

        this.derivedKey = SCryptUtil.scrypt(
                this.saltAsHexStr + this.clientPwd, 
                this.derivedKeyAlgoMaxMemory, 
                this.derivedKeyAlgoMaxMemoryFraction, 
                this.derivedKeyAlgoMaxTime);

        /**
         * The calculated derived key is encrypted.
         * ATTENTION: The derived key is a string in a specific format, its encrypted
         * form is represented as a HexString.
         */
        return this.cipher.encrypt(
                this.keyAsHexStr, 
                Hex.encodeHexString(
                        this.derivedKey.getBytes(
                                StandardCharsets.US_ASCII)));
    }

    /**
     * Encrypts the salt, and returns the HexStr representation 
     * of the encrypted data 
     * @throws CipherException 
     * @return
     */
    public String getEncryptedSaltAsHexStr() throws CipherException {

        return this.cipher.encrypt(
                this.keyAsHexStr, this.saltAsHexStr);
    }

    /**
     * Gets the Initial Vector As HexStr
     * @return
     */
    public String getInitialVectorAsHexStr() {

        return this.initialVectorAsHexStr;
    }

    /**
     * Returns the cipher that is used in this class
     * @return
     */
    public BlockCipherAlgorithms getCipherType(){
        return this.cipherType;
    }
}
