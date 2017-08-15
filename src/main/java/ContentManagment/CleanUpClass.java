package ContentManagment;

import Exceptions.UriNotFoundException;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

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
        Map<String,String> cleanedMap = new HashMap<String, String>();

        String MapUri = list.get(0).get("URI");
        cleanedMap.put("URI",MapUri);
        cleanedArray.add(cleanedMap);




        for (int i = 1; i < list.size(); i++) {
            Map<String, String> tempMap = list.get(i);
            cleanedMap = new HashMap<String, String>();


            if (MapUri.contains("cert.org")) {
                return list; //already cleaned

            }
            else if (MapUri.contains("malc0de.com")) {
                String[] tmpAr = getContFromRegex(tempMap.get("Description")+",");
                cleanedMap.put("IP",tmpAr[1]);
                cleanedMap.put("Country",tmpAr[2]);
                cleanedMap.put("ASN",tmpAr[3]);
                cleanedMap.put("MD5",tmpAr[4]);
                cleanedMap.put("HASHTYPE","MD5");

            }
            else if (MapUri.contains("malwaredomainlist.com"))
            {
                String[] tmpAr = getContFromRegex(tempMap.get("Description")+",");
                cleanedMap.put("Host",tmpAr[0]);
                cleanedMap.put("IP",tmpAr[1]);
                cleanedMap.put("ASN",tmpAr[2]);
                cleanedMap.put("COUNTRY",tmpAr[3]);
                cleanedMap.put("Description",tmpAr[4]);
            }
            else if (MapUri.contains("projecthoneypot.org")) {
                    //System.out.println(tempMap.get("Title"));
                    String[] table = tempMap.get("Title").split("\\|");
                    cleanedMap.put("IP",table[0]);
                    cleanedMap.put("Cat",new HelperMethods().getIpCategory(table[1]));
                }
            else if(MapUri.contains("malekal.com"))
            {
                Document doc = Jsoup.parse(tempMap.get("Description"));
                Elements aEl = doc.select("a");

                cleanedMap.put("HASHVALUE",tempMap.get("Title"));
                cleanedMap.put("HASHTYPE","MD5");
                cleanedMap.put("reference",aEl.text());

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
                cleanedMap.put("Cat","sshd");
            }
            else if(MapUri.contains("malshare.com"))
            {
                cleanedMap.put("HASHVALUE",tempMap.get("MD5HASH"));
                cleanedMap.put("HASHTYPE","MD5");
                cleanedMap.put("reference","malshare.com/sample.php?action=detail&hash="+tempMap.get("MD5HASH"));
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

