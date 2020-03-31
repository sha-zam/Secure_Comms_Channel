Name	: Jordan Jayke Sidik
UOW ID	: 5921946

Java execution environment: JavaSE-8
Compile using Windows command prompt

Files submitted :

1) FT_Assn1_JordanJaykeSidik_5921946_Report.docx
3) Host.java
4) Client.java
5) Gen is constructed as a function inside Host.java

To compile and run:

1) Open two windows command prompt terminals 

2) Change the directory of both of the terminals to the Host and Client folder respectively using the following command
	-> cd "directory"

3) Compile both Host.java (in Host folder) and Client.java (in Client folder) in their respective terminals using the following command
	-> javac Host.java (Run in command prompt that opened Host directory)
	-> javac Client.java  (Run in command prompt that opened Client directory)

4) Run Host.java FIRST using the following command
	-> java Host

5) Host.java will then generate the necessary parameters (p,g) to BOTH Host and Client folders in the form of "parameters.txt"

5) Run Client.java using the following command
	-> java Client

6) To exit, type "exit" in either program to exit from both programs

In the case of different passwords, the public key will not be properly dercrypted, so a dummy public key is generated.  This will produce different session keys for the Host and Client.

After the message session is initiated, if either side tries to send a message, a decryption error message will be displayed, and both programs are exitted.

References for SHA-1 hashing function and RC4 encryption function are stated inside the program source codes

I have done my best in this assignment Sir! Hope i can get great marks from you:)

