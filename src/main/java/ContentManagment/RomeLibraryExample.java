package ContentManagment;

import Exceptions.UriNotFoundException;

import java.util.ArrayList;
import java.util.Map;


public class RomeLibraryExample {




    public static void main(String[] args){

        //test call to test C2 IP stix producer
      // ContentManagment.StixProducer.produce("192.168.1.1","Harvester");

        System.out.println(getCont());
        /*
        try {
            ArrayList<Map<String,String>> parsedCont = ParsersFromRssClass.parseRssFeeds("http://www.malshare.com");

            ArrayList<Map<String,String>> cleanedCont = CleanUpClass.cleanUp(parsedCont);


        } catch (UriNotFoundException e) {
            e.printStackTrace();
        }

        System.out.println(getCont());


    */

    }

    public static String getCont()
    {
           return StixProducer.produce("192.182.1.256","ABCC");

    }

    public static String test()
    {
        return "1213424";
    }
}