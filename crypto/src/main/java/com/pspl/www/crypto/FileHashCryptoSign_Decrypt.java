/**
 * 
 */
package com.pspl.www.crypto;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * @author C1267
 *
 */
public class FileHashCryptoSign_Decrypt {

	/**
	 * @param args
	 */
	private static Cipher cipherfun;

	public static String strTAXiONDownloadedEncryptedFileLocation = "TAXiONDownloadedFile_Encrypted\\";
	public static String strTAXiONDownloadedOpenFileLocation = "TAXiONDownloadedFile_Open\\";

	//UAT Key
	static String strPubKeyPath_TAXiON = "TaxEngineKey\\TAXiONKey\\TCS_20210127_20210127_PUB.key";
	static String strPvtKeyPath = "TaxEngineKey\\PSPLRSAKey\\privateKey";
	static String strEncSymmetricKeyPath = "TaxEngineKey\\TAXiONKey\\SBI_Shared_20210115_20210115.key";
	
	//Production Key
//	static String strPvtKeyPath = "TaxEngineKey_PRODUCTION\\PSPLRSAKey\\privateKey";
//	static String strPubKeyPath_TAXiON = "TaxEngineKey_PRODUCTION\\TAXiONKey\\TCS_PROD_20210304_20210304_PUB.key";
//	static String strEncSymmetricKeyPath = "TaxEngineKey_PRODUCTION\\TAXiONKey\\PROD_ENC_Shared_20210304_20210304.key";
	
	static String strEncSourceFile = "";
	static String strDecSourceFile = "";
	static String strENCSourceFile_HASHSign = "";
	

	private static String getFileChecksum(MessageDigest digest, File file) throws IOException {
		// Get file input stream for reading the file content
		FileInputStream fis = new FileInputStream(file);

		// Create byte array to read data in chunks
		byte[] byteArray = new byte[1024];
		int bytesCount = 0;

		// Read file data and update in message digest
		while ((bytesCount = fis.read(byteArray)) != -1) {
			digest.update(byteArray, 0, bytesCount);
		}
		;

		// close the stream; We don't need it now.
		fis.close();

		// Get the hash's bytes
		byte[] bytes = digest.digest();

		// This bytes[] has bytes in decimal format;
		// Convert it to hexadecimal format
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < bytes.length; i++) {
			sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
		}

		// return complete hash
		return sb.toString();
	}

	public static PrivateKey get(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	private static void writeToFile(File output, byte[] toWrite)
			throws IllegalBlockSizeException, BadPaddingException, IOException {

		output.getParentFile().mkdirs();
		FileOutputStream fos = new FileOutputStream(output);
		fos.write(toWrite);
		fos.flush();
		fos.close();
		// System.out.println("\nThe file was successfully decrypted and stored in: " +
		// output.getPath());

	}

	public static byte[] getFileInBytes(File f) throws IOException {

		FileInputStream fis = new FileInputStream(f);
		byte[] fbytes = new byte[(int) f.length()];
		fis.read(fbytes);
		fis.close();
		return fbytes;

	}

	public void decryptFile(byte[] input, File output, PrivateKey key) throws IOException, GeneralSecurityException {

		cipherfun.init(Cipher.DECRYPT_MODE, key);
		writeToFile(output, this.cipherfun.doFinal(input));

	}

	// Method to retrieve the Public Key from a file
	public static PublicKey getPublic(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	public static void main(String[] args) throws InvalidKeyException, Exception {
		// TODO Auto-generated method stub

		File[] listOfFiles = new File(strTAXiONDownloadedEncryptedFileLocation).listFiles();

		// listFilesForFolder(SourceFile_folder);

		if (listOfFiles.length > 0) {

			System.out.println("\n Total File found -" + listOfFiles.length);

		//	FileInputStream inp = new FileInputStream(strEncSymmetricKeyPath);

			// Loading TAXiON RSA 2048 public key
			PublicKey pub = null;
			{
				byte[] bytes = Files.readAllBytes(Paths.get(strPubKeyPath_TAXiON));
				X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
				KeyFactory kf = KeyFactory.getInstance("RSA");
				pub = kf.generatePublic(ks);
			}

			// Reading Encrypted Symmetric Key
			SecretKeySpec skey = null;
			{
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.DECRYPT_MODE, get(strPvtKeyPath)); // B's private key here
				//byte[] b = new byte[256];
				//inp.read(b);
				byte[] encryptedKey = Files.readAllBytes(Paths.get(strEncSymmetricKeyPath));
				byte[] keyb = cipher.doFinal(encryptedKey);
				skey = new SecretKeySpec(keyb, 0, keyb.length, "AES");
			}

			for (final File fileEntry : listOfFiles) {

				System.out.println("\n" + fileEntry.getName());
				// Reading Source file in open format

				if (fileEntry.getName().endsWith(".csv")) {
					
					strEncSourceFile = strTAXiONDownloadedEncryptedFileLocation + fileEntry.getName();
					strDecSourceFile = strTAXiONDownloadedOpenFileLocation + fileEntry.getName();
				//	strENCSourceFile_HASHSign=

					try {
						// Decrypt the File with AES/ECB/PKCS5Padding

						Cipher ci = Cipher.getInstance("AES/ECB/PKCS5Padding");
						ci.init(Cipher.DECRYPT_MODE, skey);
						writeToFile(new File(strDecSourceFile), ci.doFinal(getFileInBytes(new File(strEncSourceFile))));

						System.out.print("\nDecryption of file - " + strEncSourceFile + " has been completed");

						// Get the SHA-256 HASH of Decrypted File
						MessageDigest shaDigest = MessageDigest.getInstance("SHA-256");
						String shaChecksum = getFileChecksum(shaDigest, new File(strDecSourceFile));

						System.out.print("\nChecksum of the file is - " + shaChecksum);
						
						File HashFileofEncryptedFile = new File(strTAXiONDownloadedEncryptedFileLocation + fileEntry.getName()+"_"+shaChecksum); 
						strENCSourceFile_HASHSign=strTAXiONDownloadedEncryptedFileLocation + fileEntry.getName()+"_"+shaChecksum;
						// Validating the HASH
//						if (strENCSourceFile_HASHSign.replace(strEncSourceFile + "_", "").equals(shaChecksum)) {
						if(HashFileofEncryptedFile.exists()) {
							System.out.print("\nChecksum matched - " + strENCSourceFile_HASHSign);

							// Validating Signature
							Signature sig = Signature.getInstance("SHA1withRSA");
							sig.initVerify(getPublic(strPubKeyPath_TAXiON));
							sig.update(getFileInBytes(new File(strEncSourceFile)));
							if (sig.verify(getFileInBytes(new File(strENCSourceFile_HASHSign)))) {
								System.out.print("\nSignature Matching Status - True");
								HashFileofEncryptedFile.delete();
								fileEntry.delete();
								// + sig.verify(getFileInBytes(new File(strENCSourceFile_HASHSign))));
							} else {
								System.out.print("\nSignature Matching Status - False");
							}
						} else {
							System.out.print("\nChecksum not matched - "
									+ strENCSourceFile_HASHSign.replace(strEncSourceFile + "_", ""));

						}

					} catch (Exception ex) {
						System.out.print("\nException - " + ex.getMessage().toString());
					}

				}
			}
		} else {
			System.out.println("\nNo File found");
		}
	}

}
