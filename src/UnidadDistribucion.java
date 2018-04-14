import java.io.BufferedReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;

import javax.crypto.SecretKey;

public class UnidadDistribucion extends Thread{

	private final static String IP = "localhost";
	private int PUERTO = 8080;
	
	
	private String INIC = "HOLA";
	private String ALG = "ALGORITMOS";
	private String CERTIFICADOCL = "CERCLNT";
	private String CERTIFICADOSV = "CERSRV";
	
	
	//Simétricos
	public final static String BLOWFISH = "BLOWFISH";
	public final static String AES = "AES";
	
	//Asimétrico
	public final static String RSA = "RSA";
	
	//HMAC
	public final static String HMACMD5 = "HMACMD5";
	public final static String HMACSHA1 = "HMACSHA1";
	public final static String HMACSHA256 = "HMACSHA256";
	
	
	public final static String SG = ":";
	public final static String ESTADO = "ESTADO";
	public final static String OK = "OK";
	public final static String ERROR = "ERROR";
	
	private String algs;
	private String sim;
	private String asim;
	private String hmac;
	
	private Socket skt = null; 
	private PrintWriter escritor = null; 
	private BufferedReader lector = null;
	
	private KeyPair keyPair;
	private SecretKey llaveSim;
	
	public UnidadDistribucion() {
		sim = BLOWFISH;
		//sim = AES;
		
		asim = RSA;
		
		hmac = HMACMD5;
//		hmac = HMACSHA1;
//		hmac = HMACSHA256;
		
		
	}
	
	public void asignarAlgoritmos(){
		algs = ALG + SG + sim + SG + asim + SG + hmac;
	}
	
	
	
	
	@Override
	public void run() {
		asignarAlgoritmos();
		
	}
	public static void main(String[] args) {	
		UnidadDistribucion cli = new UnidadDistribucion();
		cli.start();
		
	}
}
