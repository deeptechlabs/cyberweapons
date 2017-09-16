//package UK.co.demon.windsong.tines.pegwit;
import java.io.*;
/**
 * Some messages
 * @author Java conversion by Mr. Tines<tines@windsong.demon.co.uk>
 * @version 1.0, 6-Jul-1997
 */


public class PegwitMsg {
	public static final String escape = "## ";
   	public static final String leadEscape = "##";
   	public static final String from = "FROM ";
	public static final String warn_long_line =
  		"Very long line - > 8k bytes.  Binary file?\n"+
  		"Clearsignature dubious\n";
	public static final String warn_control_chars =
  		"Large number of control characters.  Binary file?\n"+
  		"Clearsignature dubious\n";
	public static final String begin_clearsign = "###\n";
	public static final String end_clearsign = "### end pegwit v8 signed text\n";
}
