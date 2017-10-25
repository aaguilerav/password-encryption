package research.crypto.main;

/**
 * 
 * @author Alejandro Aguilera Vega
 *
 */
public enum CipherExceptionCauses {

	NoSuchAlgorithm("The Algorithm specified doesn't exists. "),
	NoSuchPadding("The type of padding specified doen't exists. "),
	InvalidKey("Invalid key size, or it is null. "),
	IllegalBlockSize("The block size specified is not valid. "),
	BadPadding("Bad Padding. "),
	DecoderError("Something happened trying to convert HexString to Bytes. "),
	InvalidAlgorithmParameter("The parameter used as additional input for the algorithm, is invalid. "),
	InvalidInitialVector("The algorithm needs a valid Initial Vector. "),
	InputDataCannotBeNull("The input data provided is null. "),
	InitialVectorNeeded("This type of cipher needs an Initial Vector. "),
	InitialVectorNotNecessary("An Initial Vector is not necessary for this type of cipher. "),
	InvalidNullInput("Null input parameters are not allowed. "),
	Unknown("We can scream now :-O ");

	/**
	 * 
	 */
	private String errorDescription;

	/**
	 * 
	 * @param errorDescription
	 */
	CipherExceptionCauses(final String errorDescription){
		this.errorDescription = errorDescription;
	}

	/**
	 * 
	 * @return
	 */
	public String getErrorDescription(){
		return this.errorDescription;
	}
}
