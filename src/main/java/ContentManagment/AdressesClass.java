package ContentManagment;

import java.util.ArrayList;

/**
 * Created by gerry on 4/14/2017.
 */
public class AdressesClass {

     private static String uri1 = "http://www.projecthoneypot.org/list_of_ips.php?rss=1";
     private static String uri2 = "http://malc0de.com/rss/";
     private static String uri3 = "http://www.malwaredomainlist.com/hostslist/mdl.xml";
     private static String uri4 = "http://www.kb.cert.org/vulfeed";
     private static String uri5 = "http://www.malshare.com";
     private static String uri6 = "http://www.threatexpert.com/latest_threat_reports.aspx";
     private static String uri7 = "http://malwaredb.malekal.com/rss.php";
     private static String uri8 = "http://malwared.malwaremustdie.org/rss.php";



    public static ArrayList<String> getUrls()
    {
        ArrayList<String>  uriArList = new ArrayList<String>();
        uriArList.add(uri1);
        uriArList.add(uri2);
        uriArList.add(uri3);
        uriArList.add(uri4);
        uriArList.add(uri5);
        uriArList.add(uri6);
        uriArList.add(uri7);
        uriArList.add(uri8);

        return uriArList;
    }




}
