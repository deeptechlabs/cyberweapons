//package UK.co.demon.windsong.tines.pegwit;
import java.io.*;
/*
  pegwit by George Barwood <george.barwood@dial.pipex.com>
  100% Public Domain
  clearsigning code by Mr. Tines <tines@windsong.demon.co.uk>
  also the filter mode support.
 *
 * @author Java conversion by Mr. Tines<tines@windsong.demon.co.uk>

 This is the command line interface.

*/

public class PegwitCLI {

	private static void manual()
   	{
   		System.out.print(Pegwit.manual);
   	}

   	private static void filterManual()
   	{
   		System.out.print(Pegwit.filterManual);
   	}

   	private static boolean filter = false;
   	private static char operation = '?';

   	private static void doOperation(String[] args)
   	{
   		String message = null;
   		try{
      		String defaultPath = System.getProperty("user.dir");
   			switch(operation)
      		{
      		case 'i': //"-i <secret-key >public-key\n"
				message = Pegwit.keygen(
            				System.in,
               				new DataOutputStream(System.out)
            				);
            		break;
			case 's': //"-s plain <secret-key >signature\n"
			{
				File plain = new File(defaultPath, args[1]);
            		int value = Pegwit.sign(
            				System.in,
                           		new FileInputStream(plain),
                           		new DataOutputStream(System.out)
                           		);
            		if(value != 0) message="Unexpected failure in signature.";
				else System.out.flush();
            		break;
         		}
         		case 'v': //"-v public-key plain <signature\n"
         		{
         			File publicKey = new File(defaultPath, args[1]);
            		File plain = new File(defaultPath, args[2]);
            		int value = Pegwit.verify(
            				Pegwit.get_Pubkey(new FileInputStream(publicKey)),
                           		System.in,
                           		new FileInputStream(plain)
                           		);
				if(value !=0) message = Pegwit.err_signature;
				else message = "Signature checked OK";
            		break;
         		}
         		case 'e': //"-e public-key plain cipher <random-junk\n"
         		{
         			File publicKey = new File(defaultPath, args[1]);
            		File plain = new File(defaultPath, args[2]);
            		File cipher = new File(defaultPath, args[3]);
            		int value = Pegwit.pkEncrypt(
            				Pegwit.get_Pubkey(new FileInputStream(publicKey)),
                           		System.in,
                           		new FileInputStream(plain),
                           		new FileOutputStream(cipher)
                           		);
            		if(value != 0) message="Unexpected failure in encryption.";
            		break;
         		}
			case 'd':  //"-d cipher plain <secret-key\n"
         		{
         			File cipher = new File(defaultPath, args[1]);
            		File plain = new File(defaultPath, args[2]);
            		int value = Pegwit.pkDecrypt(
            				System.in,
                           		new FileInputStream(cipher),
                           		new FileOutputStream(plain)
            				);
            		if(value != 0) message = Pegwit.err_decrypt;
            		break;
        	 	}
         		case 'E': //"-E plain cipher <key\n"
			{
         			File plain = new File(defaultPath, args[1]);
            		File cipher = new File(defaultPath, args[2]);
				int value = Pegwit.ckEncrypt(
            				System.in,
                           		new FileInputStream(plain),
                           		new FileOutputStream(cipher)
            				);
            		if(value != 0) message = "Unexpected failure in encryption.";
            		break;

         		}
			case 'D': //"-D cipher plain <key\n"
         		{
         			File cipher = new File(defaultPath, args[1]);
            		File plain = new File(defaultPath, args[2]);
            		int value = Pegwit.ckDecrypt(
            				System.in,
                           		new FileInputStream(cipher),
                           		new FileOutputStream(plain)
            				);
            		if(value != 0) message = Pegwit.err_decrypt;
            		break;
         		}
			case 'S': //"-S text <secret-key >clearsigned-text\n"
         		{
         			File text = new File(defaultPath, args[1]);
            		message = Pegwit.clearsign(
            				System.in,
            				new DataInputStream( new FileInputStream(text)),
                           		new DataOutputStream(System.out)
                           		);
            		break;
         		}
         		case 'V': //"-V public-key clearsigned-text >text\n"
         		{
         			File publicKey = new File(defaultPath, args[1]);
            		File clear = new File(defaultPath, args[2]);
            		DataInputStream clearStream =
            					new DataInputStream( new FileInputStream(clear));
            		if(!Pegwit.position(clearStream))
            			message=Pegwit.err_clearsig_header_not_found;
            		else
            		{
            			int value = Pegwit.clearverify(
            					Pegwit.get_Pubkey(new FileInputStream(publicKey)),
							clearStream,
                           			new DataOutputStream(System.out)
                           			);
					if(value !=0) message = Pegwit.err_signature;
					else message = "Signature checked OK";
				}
         			break;
			}
         		default:
   				message = "Unknown option!";
      		}// end switch
		} catch (Exception e) {
			message = "Exception : "+e.getMessage();
			e.printStackTrace(System.err);
		}
      	if(message != null) System.err.println("Status: "+message);
   	}

   	private static void doFilter(String[] args)
   	{
   		String message = null;
   		try{
      		String defaultPath = System.getProperty("user.dir");
   			switch(operation)
      		{
         		case 'e': //"-fe public-key random-junk <plain >ascii-cipher\n"
         		{
         			File publicKey = new File(defaultPath, args[1]);
            		File junk = new File(defaultPath, args[2]);
            		int value = Pegwit.pkEncrypt(
            				Pegwit.get_Pubkey(new FileInputStream(publicKey)),
                           		new FileInputStream(junk),
                           		System.in,
                           		new Base64Output(new DataOutputStream(System.out))
                           		);
            		if(value != 0) message="Unexpected failure in encryption.";
            		break;
         		}
			case 'd':  //  "-fd secret-key <ascii-cipher >plain\n"
         		{
         			File secretKey = new File(defaultPath, args[1]);
            		DataInputStream cypherStream =
            				new DataInputStream(System.in);
            		if(!Pegwit.position(cypherStream))
            			message=Pegwit.err_clearsig_header_not_found;
            		else
            		{
            			int value = Pegwit.pkDecrypt(
                           			new FileInputStream(secretKey),
                           			new Base64Input(cypherStream),
                           			System.out
            					);
            			if(value != 0) message = Pegwit.err_decrypt;
            		}
            		break;
         		}
         		case 'E': //"-fE key <plain >ascii-cipher\n"
			{
         			File key = new File(defaultPath, args[1]);
				int value = Pegwit.ckEncrypt(
            					new FileInputStream(key),
                           			System.in,
                           			new Base64Output(new DataOutputStream(System.out))
            					);
            		if(value != 0) message = "Unexpected failure in encryption.";
            		break;
         		}
			case 'D': //"-fD key <ascii-cipher >plain\n"
         		{
         			File key = new File(defaultPath, args[1]);
            		DataInputStream cypherStream =
            					new DataInputStream(System.in);
            		if(!Pegwit.position(cypherStream))
            			message=Pegwit.err_clearsig_header_not_found;
            		else
            		{
            			int value = Pegwit.ckDecrypt(
            					new FileInputStream(key),
                           			new Base64Input(cypherStream),
                           			System.out
            					);
            			if(value != 0) message = Pegwit.err_decrypt;
            		}
            		break;
         		}
			case 'S': //"-fS secret-key <text >clearsigned-text\n"
         		{
         			File secretKey = new File(defaultPath, args[1]);
            		message = Pegwit.clearsign(
            				new FileInputStream(secretKey),
            				new DataInputStream(System.in),
                           		new DataOutputStream(System.out)
                           		);
            		break;
         		}
         		case 'V': //"-fV public-key <clearsigned-text >text\n";
         		{
         			File publicKey = new File(defaultPath, args[1]);
            		DataInputStream clearStream =
            					new DataInputStream(System.in);
            		if(!Pegwit.position(clearStream))
            			message=Pegwit.err_clearsig_header_not_found;
            		else
            		{
            			int value = Pegwit.clearverify(
            					Pegwit.get_Pubkey(new FileInputStream(publicKey)),
							clearStream,
                           			new DataOutputStream(System.out)
                           			);
					if(value !=0) message = Pegwit.err_signature;
					else message = "Signature checked OK";
				}
         			break;
			}
         		default:
   				message = "Unknown option!";
      		}// end switch
		} catch (Exception e) {
			message = "Exception : "+e.getMessage();
			e.printStackTrace(System.err);
		}
      	if(message != null) System.err.println(message);
   	}

   	public static void main(String[] args)
   	{
   		if((args.length < 1) ||
      	(args[0].length()<2) ||
      	(args[0].charAt(0) != '-'))
      	{
         		manual();
         		return;
      	}

      	operation = args[0].charAt(1);

  		if('f' == operation)
  		{
      		filter=true;
         		if(args[0].length() != 3)
         		{
         			filterManual();
            		return;
         		}
         		operation = args[0].charAt(2);
      	}
      	else if(args[0].length() != 2)
      	{
      		manual();
         		return;
		}

  		/* Check the number of arguments */
  		int expect = 0;

  		if(!filter)
  		{
    			if ( operation == 'i' ) expect = 1;
    			else if ( operation == 's' || 'S' == operation ) expect = 2;
    			else if ( operation == 'd' || operation == 'v' || 'V' == operation ||
    			operation == 'D' || operation == 'E' ) expect = 3;
    			else if ( operation == 'e' ) expect = 4;
         		if(args.length != expect)
         			manual();
         		else doOperation(args);
  		}
  		else
  		{
    			if('V' == operation || 'S' == operation || 'E' == operation ||
      		'D' == operation || 'd' == operation ) expect = 2;
   			else if ('e' == operation) expect = 3;
         		if(args.length != expect)
         			filterManual();
			else doFilter(args);
  		}
		return;
	}
}

