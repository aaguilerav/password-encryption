package research.crypto.main;

import java.security.GeneralSecurityException;

/**
 * 
 * @author Alejandro Aguilera Vega
 * 
 */
public class CipherException extends GeneralSecurityException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private CipherExceptionCauses cause;

	/**
	 * 
	 * @param cause
	 */
	public CipherException(CipherExceptionCauses cause){
		super(cause.getErrorDescription());
		this.cause = cause;
	}

	/**
	 * 
	 * @param cause
	 */
	public CipherException(CipherExceptionCauses cause, String comments){
		super(cause.getErrorDescription() + comments);
		this.cause = cause;
	}

	/**
	 * 
	 * @param ex
	 * @param cause
	 */
	public CipherException(Exception ex, CipherExceptionCauses cause){
		super(ex.getMessage());
		this.cause = cause;
		this.setStackTrace(ex.getStackTrace());
	}

	/**
	 * 
	 * @return
	 */
	public CipherExceptionCauses getExceptionCause()
	{
		return this.cause;
	}
}
