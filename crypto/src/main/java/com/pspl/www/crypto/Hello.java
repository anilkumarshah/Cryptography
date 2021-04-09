package com.pspl.www.crypto;

import java.io.File;

public class Hello {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
System.out.print("Welcome");
String strOpenFileLocation = "SourceFile_Open\\";
File[] listOfFiles = new File(strOpenFileLocation).listFiles();
System.out.print("\nTotal File="+ listOfFiles.length); 
	}

}
