import java.security.KeyPair;

import javax.crypto.SecretKey;

public class UnidadDistribucion {

	private final static String ip = "localhost";
	private int PUERTO = 8080;
	private String INIC = "HOLA";
	private String ALG = "ALGORITMOS";
	private String CERTIFICADOCL = "CERCLNT";
	private String CERTIFICADOSV = "CERSRV";
	private String ALGS = "AES";
	private String ALGA = "RSA";
	private String ALGD = "HMACSHA1";
	private String SG = ":";
	
	private KeyPair keyPair;
	private SecretKey llaveSim;
}
