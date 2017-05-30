import Exceptions.UriNotFoundException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by gerry on 4/14/2017.
 */
public class CleanUpClass {

    public static ArrayList<Map<String, String>> cleanUp(ArrayList<Map<String, String>> list) throws UriNotFoundException {
        ArrayList<Map<String,String>> cleanedArray = new ArrayList<Map<String, String>>();

        for (int i = 1; i < list.size(); i++) {
            Map<String, String> tempMap = list.get(0);
            Map<String,String> cleanedMap = new HashMap<String, String>();
            String MapUri = tempMap.get("URI");

            cleanedMap.put("URI",MapUri);
            if (MapUri.contains("cert.org")) {
                return list; //already cleaned

            }
            else if (MapUri.contains("malc0de.com")) {
                String[] tmpAr = getContFromRegex(tempMap.get("Description")+",");
                cleanedMap.put("URL",tmpAr[0]);
                cleanedMap.put("IP",tmpAr[1]);
                cleanedMap.put("Country",tmpAr[2]);
                cleanedMap.put("ASN",tmpAr[3]);
                cleanedMap.put("MD5",tmpAr[4]);
            }
            else if (MapUri.contains("malwaredomainlist.com"))
            {
                String[] tmpAr = getContFromRegex(tempMap.get("Description")+",");
                cleanedMap.put("Host",tmpAr[0]);
                cleanedMap.put("IP",tmpAr[1]);
                cleanedMap.put("Country",tmpAr[2]);
                cleanedMap.put("ASN",tmpAr[3]);
                cleanedMap.put("Description",tmpAr[4]);
            }
            else if (MapUri.contains("projecthoneypot.org")) {
                    System.out.println(tempMap.get("Title"));
                    String[] table = tempMap.get("Title").split("\\|");
                    cleanedMap.put("IP",table[0]);
                    cleanedMap.put("Cat",new HelperMethods().getIpCategory(table[1]));
                }
            else if(MapUri.contains("malekal.com"))
            {
                String[] tmpTable =(tempMap.get("Description")).split(":");
                String reference = tmpTable[1];
                cleanedMap.put("HASHVALUE",tempMap.get("Title"));
                cleanedMap.put("reference",reference);

            }
            else if (MapUri.contains("threatexpert.com"))
            {
                cleanedMap.put("virus",tempMap.get("Title"));
            }
            else if (MapUri.contains("malwared.malwaremustdie.org/rss_bin.php"))
            {
                cleanedMap.put("virus",tempMap.get("Title"));
                cleanedMap.put("MD5",tempMap.get("Description"));
            }
            else if(MapUri.contains("malwared.malwaremustdie.org/rss_ssh.php"))
            {
                cleanedMap.put("IP",tempMap.get("Description"));
            }
            else
            {
                throw new UriNotFoundException("uri not found!!");
            }

                cleanedArray.add(cleanedMap);
            }

           return cleanedArray;
        }


    public static String[] getContFromRegex(String mydata)
    {
        String[] strTbl = new String[5];
        int i = 0;

        Pattern pattern = Pattern.compile(":(.+?),");
        Matcher matcher = pattern.matcher(mydata);
        while(matcher.find())
        {
            strTbl[i]=matcher.group(1);
            i++;
        }

        return strTbl;
    }
}
