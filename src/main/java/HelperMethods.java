import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Created by gerry on 4/23/2017.
 */
public class HelperMethods {

    private  Map<Character,String> categories;

    public HelperMethods() {
        this.categories =new HashMap<Character, String>(){{
            put('H',"Harvesters");
            put('S',"Spam Serves");
            put('W',"Bad Web Hosts");
            put('C',"Comment Spammers");
            put('D',"Dictionary Attackers");
            put('R',"Rule Breakers");
            put('e',"Search Engines");

        }};
    }


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

    public  String getIpCategory(String cat)
    {
        String category="";
        for (int i = 0; i < cat.length(); i++) {
            if(cat.charAt(i) == 'S' && i+1<cat.length() && cat.charAt(i+1) == 'e')
                category+=this.categories.get('e');
            else
            {

                System.out.println(this.categories.get(cat.charAt(i)));
                category += this.categories.get(cat.charAt(i)) + ",";
            }


        }
        return category;
    }

    //method to get curent time
    public static XMLGregorianCalendar getTime()
    {
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
}
