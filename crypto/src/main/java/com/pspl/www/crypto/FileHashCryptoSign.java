/**
 * 
 */
package com.pspl.www.crypto;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.File;
//import java.io.InputStream;
//import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author C1267
 *
 */
public class FileHashCryptoSign {

	/**
	 * @param args
	 */

	private static Cipher cipherfun;

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

	public static void EncryptData(File originalFile, File encrypted, SecretKeySpec secretKey, String cipherAlgorithm)
			throws IOException, GeneralSecurityException {

		cipherfun = Cipher.getInstance(cipherAlgorithm);
		encryptFile(getFileInBytes(originalFile), encrypted, secretKey);

	}

	public static void encryptFile(byte[] input, File output, SecretKeySpec key)
			throws IOException, GeneralSecurityException {

		cipherfun.init(Cipher.ENCRYPT_MODE, key);
		writeToFile(output, cipherfun.doFinal(input));

	}

	private static void writeToFile(File output, byte[] toWrite)
			throws IllegalBlockSizeException, BadPaddingException, IOException {

		output.getParentFile().mkdirs();
		FileOutputStream fos = new FileOutputStream(output);
		fos.write(toWrite);
		fos.flush();
		fos.close();
		System.out.println("The file was successfully encrypted and stored in: " + output.getPath());

	}

	private static void writeLog(String strFileName, String strData)
			throws IllegalBlockSizeException, BadPaddingException, IOException {

		try {
			DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");
			DateTimeFormatter dt = DateTimeFormatter.ofPattern("dd-MM-yyyy");
			LocalDateTime now = LocalDateTime.now();
			System.out.println(dtf.format(now));
			FileWriter myWriter = new FileWriter(strFileName + dt.format(now) + "txt");
			myWriter.write(dtf.format(now) + " ----- " + strData);
			myWriter.close();
			System.out.println("Successfully wrote to the file.");
		} catch (IOException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}

	}

	public static byte[] getFileInBytes(File f) throws IOException {

		FileInputStream fis = new FileInputStream(f);
		byte[] fbytes = new byte[(int) f.length()];
		fis.read(fbytes);
		fis.close();
		return fbytes;

	}

	public static void encryptFileNew(String algorithm, SecretKey key, File inputFile, File outputFile)
			throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		FileInputStream inputStream = new FileInputStream(inputFile);
		FileOutputStream outputStream = new FileOutputStream(outputFile);
		byte[] buffer = new byte[64];
		int bytesRead;
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			byte[] output = cipher.update(buffer, 0, bytesRead);
			if (output != null) {
				outputStream.write(output);
			}
		}
		byte[] outputBytes = cipher.doFinal();
		if (outputBytes != null) {
			outputStream.write(outputBytes);
		}
		inputStream.close();
		outputStream.close();
	}

	public static void main(String[] args) throws InvalidKeyException, Exception {
		// TODO Auto-generated method stub

		String strLogFile = "LogFile\\Log";
		String strOpenFileLocation = "SourceFile_Open\\";
		String strEncryptedFileLocation = "SourceFile_Encrypted\\";
		
		//UAT Key
		String strPvtKeyPath = "TaxEngineKey\\PSPLRSAKey\\privateKey";
		String strPubKeyPath_TAXiON = "TaxEngineKey\\TAXiONKey\\TCS_20210127_20210127_PUB.key";
		String strEncSymmetricKeyPath = "TaxEngineKey\\TAXiONKey\\SBI_Shared_20210115_20210115.key";
		
		//Production Key
//		String strPvtKeyPath = "TaxEngineKey_PRODUCTION\\PSPLRSAKey\\privateKey";
//		String strPubKeyPath_TAXiON = "TaxEngineKey_PRODUCTION\\TAXiONKey\\TCS_PROD_20210304_20210304_PUB.key";
//		String strEncSymmetricKeyPath = "TaxEngineKey_PRODUCTION\\TAXiONKey\\PROD_ENC_Shared_20210304_20210304.key";

		String shaChecksum = "";
		String strSourceFile = "";
		String strEncSourceFile = "";

		FileInputStream inp = new FileInputStream(strEncSymmetricKeyPath);
		// Load Public & Private Key

		// Loading all open file from source folder
		File[] listOfFiles = new File(strOpenFileLocation).listFiles();

		// listFilesForFolder(SourceFile_folder);
		try {

			if (listOfFiles.length > 0) {

				System.out.println("\n Total File found -" + listOfFiles.length);

				// Loading Encrypted AES 256 Symmetric Key, PSPL RSA 2048 Pvt Key, TAXiON Public
				// RSA 2048 Public Key

				// Loading PSPL RSA 2048 private key
				PrivateKey pvt = null;
				{
					byte[] bytes = Files.readAllBytes(Paths.get(strPvtKeyPath));
					PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
					KeyFactory kf = KeyFactory.getInstance("RSA");
					pvt = kf.generatePrivate(ks);
				}

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
					byte[] b = new byte[256];
					inp.read(b);
					byte[] keyb = cipher.doFinal(b);

					skey = new SecretKeySpec(keyb, 0, keyb.length, "AES");
					// System.out.print("Symmetric key is - " + skey.toString());

				}

				MessageDigest shaDigest = MessageDigest.getInstance("SHA-256");

				for (final File fileEntry : listOfFiles) {

					System.out.println("\n" + fileEntry.getName());
					// Reading Source file in open format
					strSourceFile = strOpenFileLocation + fileEntry.getName();
					strEncSourceFile = strEncryptedFileLocation + fileEntry.getName();
					// Get the SHA-256 HASH of File

					shaChecksum = getFileChecksum(shaDigest, new File(strSourceFile));
					System.out.print("\nChecksum of the file is - " + shaChecksum);
					writeLog(strLogFile, "Checksum of the file is - " + shaChecksum);
					// Encrypt the File with AES/ECB/PKCS5Padding
					encryptFileNew("AES/ECB/PKCS5Padding", skey, new File(strSourceFile), new File(strEncSourceFile));
					System.out
							.print("\nEncryption of the file -" + fileEntry.getName() + " has been done successfully");
					writeLog(strLogFile,
							"Encryption of the file -" + fileEntry.getName() + " has been done successfully");
					// Creating Supporting file includes Hash
					OutputStream out = new FileOutputStream(strEncSourceFile + "_" + shaChecksum);
					// Signing the file with SHA1WithRSA
					byte[] ENCSourceFilebytes = Files.readAllBytes(Paths.get(strEncSourceFile));
					Signature sign = Signature.getInstance("SHA1WithRSA");
					sign.initSign(pvt); // Sign using PSPL private key
					sign.update(ENCSourceFilebytes);
					byte[] signatureBytes = sign.sign();
					out.write(signatureBytes);
					out.close();
					System.out.println("\nFile signing of " + fileEntry.getName() + " has been completed");
					writeLog(strLogFile, "File signing of " + fileEntry.getName() + " has been completed");
					fileEntry.delete();
				}
			} else {
				System.out.println("\nNo File found");
			}
		} catch (Exception e) {
			// TODO: handle exception
			System.out.println("\n exception  -" + e.getMessage().toString());

		}
	}

}
