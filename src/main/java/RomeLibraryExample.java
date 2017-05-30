import Exceptions.UriNotFoundException;

import java.util.ArrayList;
import java.util.Map;


public class RomeLibraryExample {




    public static void main(String[] args){

        //test call to test C2 IP stix producer
      // StixProducer.produce("192.168.1.1","Harvester");



        ArrayList<Map<String,String>> parsedCont = ParsersFromRssClass.parseRssFeeds("http://www.kb.cert.org/vulfeed");
        try {
            ArrayList<Map<String,String>> cleanedCont = CleanUpClass.cleanUp(parsedCont);

           StixProducer.cveGen(cleanedCont.get(1));
        } catch (UriNotFoundException e) {
            e.printStackTrace();
        }




        System.out.println(parsedCont);
        System.out.println("----------------------------------");
            System.out.println();



    }
}