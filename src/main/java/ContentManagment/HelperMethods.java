package ContentManagment;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Created by gerry on 4/23/2017.
 */
public class HelperMethods {

    private Map<Character, String> categories;

    public HelperMethods() {
        this.categories = new HashMap<Character, String>() {{
            put('H', "Harvesters");
            put('S', "Spam Serves");
            put('W', "Bad Web Hosts");
            put('C', "Comment Spammers");
            put('D', "Dictionary Attackers");
            put('R', "Rule Breakers");
            put('e', "Search Engines");

        }};
    }


    //Gets a string a trannsforms it to a XMLGregorianCalendar object which is accepted in the stix specification.

    static XMLGregorianCalendar getDateFromString(String dateStr) {
        DateFormat df = new SimpleDateFormat("dd MMM yyyy");
        Date date = null;
        try {
            date = df.parse(dateStr);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        GregorianCalendar cal = new GregorianCalendar();


        cal.setTime(date);

        XMLGregorianCalendar date2 = null;
        try {
            date2 = DatatypeFactory.newInstance().newXMLGregorianCalendar(cal);
        } catch (DatatypeConfigurationException e) {
            e.printStackTrace();
        }
        return date2;
    }

    //this method gets the acronym for IP category from ProjectHoneypot.org and returns the
    //full name of the category

    public String getIpCategory(String cat) {
        String category = "";
        for (int i = 0; i < cat.length(); i++) {
            if (cat.charAt(i) == 'S' && i + 1 < cat.length() && cat.charAt(i + 1) == 'e')
                category += this.categories.get('e');
            else {

                System.out.println(this.categories.get(cat.charAt(i)));
                category += this.categories.get(cat.charAt(i)) + ",";
            }


        }
        return category;
    }

    //method to get curent time
    public static XMLGregorianCalendar getTime() {
        XMLGregorianCalendar now = null;
        try {
            now = DatatypeFactory.newInstance()
                    .newXMLGregorianCalendar(
                            new GregorianCalendar(TimeZone.getTimeZone("UTC")));
        } catch (DatatypeConfigurationException e) {
            e.printStackTrace();
        }
        return now;
    }


    //Accepts an arraylist  of file paths and puts all the files in a zip archive file.
    public static File FilesToZip(ArrayList<String> ftp, String outName) {

        String homeDir = System.getProperty("java.io.tmpdir");
        File file = new File(homeDir,outName);
        if(file.exists())
            file.delete();

        try {

            // create byte buffer
            byte[] buffer = new byte[1024];

            FileOutputStream fos = new FileOutputStream(file);

            ZipOutputStream zos = new ZipOutputStream(fos);

            for (int i=0; i < ftp.size(); i++) {

                File srcFile = new File(ftp.get(i));

                FileInputStream fis = new FileInputStream(srcFile);

                // begin writing a new ZIP entry, positions the stream to the start of the entry data
                zos.putNextEntry(new ZipEntry(srcFile.getName()));

                int length;

                while ((length = fis.read(buffer)) > 0) {
                    zos.write(buffer, 0, length);
                }

                zos.closeEntry();

                // close the InputStream
                fis.close();

            }

            // close the ZipOutputStream
            zos.close();

        }
        catch (IOException ioe) {
            System.out.println("Error creating zip file: " + ioe);
        }
        return file;


    }



    //Accepts a stix file path and extracts the stix unique ID.
    public static String getStixName(String file) {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = null;
        try {
            docBuilder = docBuilderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        }
        Document doc = null;
        String id2 = null;
        File fileToRead = new File(file);
        InputStream in = null;
        try {

            in = new FileInputStream(fileToRead);
            doc = docBuilder.parse(in);


            id2 = doc.getFirstChild().getAttributes().item(0).getNodeValue();
            String[] tmpAr = id2.split(":");
            id2 = tmpAr[1];
        } catch (SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            try {
                in.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }


        return id2;
    }


    //this method will help conver a short name ie: "cert" to the actual source url
    public static String getSourceFromName(String name)
    {
        ArrayList<String> sources = AdressesClass.getUrls();

        for (int i = 0; i < sources.size() ; i++) {
            if(sources.get(i).contains(name))
                return sources.get(i);
        }

        return null;
    }
}
