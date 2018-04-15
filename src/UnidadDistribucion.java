import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;


import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;

import sun.security.x509.*;
import java.security.cert.*;
import java.security.*;
import java.math.BigInteger;
import java.util.Collections;
import java.util.Date;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
public class UnidadDistribucion{

	private final static String IP = "localhost";
	private int PUERTO = 4443;


	private String INIC = "INICIO";
	private String ALG = "ALGORITMOS";
	private String CERTIFICADOCL = "CERTCLNT";
	private String CERTIFICADOSV = "CERTSRV";


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
	public final static String ACT1 = "ACT1";
	public final static String ACT2 = "ACT2";

	private String algs;
	private String sim;
	private String asim;
	private String hmac;

	private Socket skt; 
	private PrintWriter out; 
	private BufferedReader in;
	private InputStream is;

	private KeyPair keyPair;
	private SecretKey llaveSim;
	private byte[] llaveCreada;

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



	public void inicializar() throws Exception {
		asignarAlgoritmos();
		try{
			skt = new Socket(IP, PUERTO);
			out = new PrintWriter(skt.getOutputStream(), true);
			is = skt.getInputStream();
			in = new BufferedReader(new InputStreamReader(is));
		}
		catch(Exception e){
			System.out.println("No inició nada del Stream");
		}
		generarLlaves();
		if(PUERTO == 4444){
			conexion4444();
		}
		else if(PUERTO == 4443){
			conexion4443();
			System.out.println("3");
		}
		else{
			System.out.println("No hay puerto papi");
		}

	}

	public static void main(String[] args) throws Exception{
		UnidadDistribucion cli = new UnidadDistribucion();
		cli.inicializar();
	}

	private void generarLlaves() {
		KeyPairGenerator gen;
		try {
			gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(1024);
			keyPair = gen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			System.out.println("fallo al generar las llaves");
			e.printStackTrace();
		}


	}

	public void conexion4444() throws Exception
	{

		out.println("HOLA");
		String respuesta = in.readLine();
		if(respuesta.equals(INIC))
		{
			out.println(algs);

			if(in.readLine().equals(ESTADO+SG+OK))
			{
				out.println(CERTIFICADOCL);

				X509Certificate cert = generateV3Certificate(this.keyPair);
				imprimircert(cert);
				//				skt.getOutputStream().write(flujoDeBytes);
				//				skt.getOutputStream().flush();
				if(in.readLine().equals(ESTADO+SG+OK)){
					if(in.readLine().equals(CERTIFICADOSV)){
						out.println(ESTADO+SG+OK);
						if(in.readLine().equals(INIC)){
							out.println(ACT1);
							out.println(ACT2);
						}
					}
				}
				//				System.out.println("respuesta: "+in.readLine());
			}
			else if(respuesta.equals("ERROR"))
			{
				System.out.println("ERROR EN EL SERVIDOR");
			}
		}	
	}



	public void conexion4443() throws Exception
	{

		out.println("HOLA");
		String respuesta = in.readLine();
		if(respuesta.equals(INIC))
		{
			out.println(algs);

			if(in.readLine().equals(ESTADO+SG+OK))
			{
				out.println(CERTIFICADOCL);
				X509Certificate cert = generateV3Certificate(this.keyPair);
				imprimircert(cert);
				//					out.println(ESTADO+SG+OK);
				if(in.readLine().equals(ESTADO+SG+OK)){
					if(in.readLine().equals(CERTIFICADOSV)){
						X509Certificate certServ = 	leerCertificado();
						//out.println(ESTADO+SG+OK);
						String[] resp = (in.readLine()).split(":");
						llaveCreada = descifrar(DatatypeConverter.parseHexBinary(resp[1]), asim, this.keyPair.getPrivate());
						llaveSim = new SecretKeySpec(llaveCreada, 0, llaveCreada.length, sim);

						//COORDENADAS
						String coordenadas = "4.46,5.16";


						byte[] act1A = cifrar(coordenadas.getBytes(), sim, llaveSim);
						String act1 = hexadecimal(act1A);
						out.println(ACT1 + ":" + act1);

						// Paso 12
						byte[] integridad = generarIntegridad(coordenadas.getBytes(), hmac, llaveSim);
						byte[] act2A = cifrar(integridad, asim, certServ.getPublicKey());
						String act2 = hexadecimal(act2A);
						out.println(ACT2 + ":" + act2);
					}
				}
			}



			//				if(in.readLine().equals(CERTIFICADOSV)){
			//					out.println(ESTADO+SG+OK);
			//					X509Certificate certServ = 	leerCertificado();
			//					byte[] arr = leerllave();
			//					llaveSim = descifrar(arr);
			//					byte[] cifrada = cifrarLlave(certServ.getPublicKey());
			//					String codificada = codificarHex(cifrada);
			//					out.println(codificada);
			//					consultar();
			//					String serv =in.readLine();
			//					leerResultado(serv);
			//				}

		}
		else if(respuesta.equals("ERROR"))
		{
			System.out.println("ERROR EN EL SERVIDOR");
		}
	}


	/**
	 * Se genera un certificado digital respecto a una llave.
	 * En el certificado debe existir la información que genere losa datos de la entidad.
	 * @param Keypair pair 
	 * @return X509Certificate
	 * @throws Exception
	 */
	public static X509Certificate generateV3Certificate(KeyPair pair) throws Exception {
		X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		nameBuilder.addRDN(BCStyle.OU, "OU");
		nameBuilder.addRDN(BCStyle.O, "O");
		nameBuilder.addRDN(BCStyle.CN, "CN");
		String stringDate1 = "2016-10-01";
		String stringDate2 = "2020-12-20";
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd");
		Date notBefore = null;
		Date notAfter = null;
		try {
			notBefore = format.parse(stringDate1);
			notAfter = format.parse(stringDate2);
		}
		catch (ParseException e) {
			e.printStackTrace();
		}
		BigInteger serialNumber = new BigInteger(128, new Random());
		JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(nameBuilder.build(), serialNumber, notBefore, notAfter, nameBuilder.build(), pair.getPublic());
		X509Certificate certificate = null;
		try {
			ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(pair.getPrivate());
			certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));
		}
		catch (OperatorCreationException e) {
			e.printStackTrace();
		}
		catch (CertificateException e) {
			e.printStackTrace();
		}
		return certificate;
	}


	public byte[] generarIntegridad(byte[] mensaje, String algoritmo, Key llave) throws IOException {
		byte[] integridad = null;
		try {
			Mac generador = Mac.getInstance(algoritmo);
			generador.init(llave);
			integridad = generador.doFinal(mensaje);
		} catch (Exception e) {

		}

		return integridad;
	}

	//	public byte[] hmacDigest(byte[] msg, Key key, String algo) throws NoSuchAlgorithmException,
	//	InvalidKeyException, IllegalStateException, UnsupportedEncodingException {
	//		Mac mac = Mac.getInstance(algo);
	//		mac.init(key);
	//
	//		byte[] bytes = mac.doFinal(msg);
	//		return bytes;
	//	}

	public static byte[] symmetricDecryption (byte[] msg, Key key , String algo)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, 
			NoSuchAlgorithmException, NoSuchPaddingException {
		algo = algo + 
				(algo.equals("DES") || algo.equals("AES")?"/ECB/PKCS5Padding":"");
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.DECRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}

	public void leerResultado(String resp) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
	{
		String respuesta = codificarHex(symmetricDecryption(decodificarHex(resp), llaveSim, sim));
		System.out.println(respuesta);
	}


	public void imprimircert(X509Certificate certificado) throws Exception
	{

		PemWriter pWrt = new PemWriter(out);
		PemObject pemObj = new PemObject("CERTIFICATE",Collections.EMPTY_LIST, certificado.getEncoded());
		pWrt.writeObject(pemObj);
		pWrt.flush();
	}

	public X509Certificate leerCertificado() throws IOException
	{
		X509Certificate cert = null;
		//	byte[] certificadoClienteBytes = new byte['ᎈ'];
		//		is.read(certificadoClienteBytes);
		//		InputStream inputStream = new ByteArrayInputStream(certificadoClienteBytes);
		try {
			cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
			System.out.println(cert.toString());
			out.println(ESTADO+SG+OK);

		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cert;
	}

	public byte[] leerllave() throws IOException
	{
		String linea = in.readLine();
		linea = in.readLine();
		byte[] llaveSimServidor = decodificarHex(linea);
		return llaveSimServidor;
	}

	public byte[] descifrar(byte[] mensaje, String algoritmo, Key llave) throws IOException {
		byte[] descifrado = null;
		try {
			Cipher descifrador = Cipher.getInstance(algoritmo); 
			descifrador.init(Cipher.DECRYPT_MODE, llave);
			descifrado = descifrador.doFinal(mensaje);
		} catch (Exception e) {

		}
		return descifrado;

	}

	public byte[] cifrar(byte[] mensaje, String algoritmo, Key llave) throws IOException {
		byte[] cifrado = null;
		try {
			Cipher cifrador = Cipher.getInstance(algoritmo);
			cifrador.init(1, llave);
			cifrado = cifrador.doFinal(mensaje);
		} catch (Exception e) {

		}

		return cifrado;
	}

	public static String hexadecimal(byte[] mensajeArreglo) {
		return DatatypeConverter.printHexBinary(mensajeArreglo);
	}

	public static byte[] symmetricEncryption (byte[] msg, Key key , String algo)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, 
			NoSuchAlgorithmException, NoSuchPaddingException {
		algo = algo + 
				(algo.equals("DES") || algo.equals("AES")?"/ECB/PKCS5Padding":"");
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.ENCRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}

	public byte[] cifrarLlave(Key key ) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		KeyGenerator keygen = KeyGenerator.getInstance(sim);
		keygen.init(128);
		SecretKey llave = keygen.generateKey();

		Cipher cifrador = Cipher.getInstance(asim);
		cifrador.init(Cipher.ENCRYPT_MODE, key);
		byte [] encriptada = cifrador.doFinal(llave.getEncoded());

		return encriptada;

	}

	public byte[] decodificarHex(String ss)
	{
		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte)Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
		return ret;
	}

	public String codificarHex (byte[] arr)
	{
		String ret = "";
		for (int i = 0 ; i < arr.length ; i++) {
			String g = Integer.toHexString(((char)arr[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
		return ret;
	}
}
