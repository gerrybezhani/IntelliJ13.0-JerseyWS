package ContentManagment;


import com.rometools.rome.feed.synd.SyndContent;
import com.rometools.rome.feed.synd.SyndEntry;
import com.rometools.rome.feed.synd.SyndFeed;
import com.rometools.rome.io.FeedException;
import com.rometools.rome.io.SyndFeedInput;
import com.rometools.rome.io.XmlReader;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

/**
 * Created by gerry on 4/13/2017.
 */
public class ParsersFromRssClass {

    public static ArrayList<Map<String,String>> parseRssFeeds(String url,int size)
    {
        if(url.contains("cert.org"))
        {

            ArrayList<Map<String,String>> test ;
            test = getContentsFromCert(size);
            return test;

        }
        else if(url.contains("malshare"))
        {
            ArrayList<Map<String,String>> tmpArList = new ArrayList<Map<String, String>>();
            Map<String,String> tmpMap = new HashMap<String, String>();
            String[] cont = getFromMalshare();

            tmpMap.put("URI",url);
            tmpArList.add(tmpMap);
            for (int i = 0; i < cont.length; i++) {
                tmpMap = new HashMap<String, String>();
                tmpMap.put("MD5HASH",cont[i]);
                tmpArList.add(tmpMap);
            }
            return tmpArList;
        }
        else
            return getContFromRssNoHtml(url,size);

    }

    private static String[] getFromMalshare() {
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(AdressesClass.getUrls().get(4) + "/api.php?api_key=" + ApiKeyClass.malshare + "&action=getlist");
        String[] splitCont = new String[0];
        try {
            CloseableHttpResponse response1 = httpclient.execute(httpGet);
            try {
                System.out.println(response1.getStatusLine());
                HttpEntity entity1 = response1.getEntity();
                String cont = EntityUtils.toString(entity1);
                splitCont = cont.split("<br>");


                EntityUtils.consume(entity1);
            } finally {
                response1.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return splitCont;
    }


    private static ArrayList<Map<String,String>> getContentsFromCert(int size)
    {
        //contents arraylist contains the HTML content section of the rss feed from CERT.OR
        ArrayList<String> contents = getFeedContents(AdressesClass.getUrls().get(3),size);
        ArrayList<Map<String,String>> allContents = new ArrayList<Map<String, String>>();
        Map<String,String> tempMap = new HashMap<String, String>();
        tempMap.put("URI",AdressesClass.getUrls().get(3));
        allContents.add(tempMap);
        for (int i = 0; i < contents.size(); i++) {

            allContents.add(HtmlParseFromCert(contents.get(i)));
        }

        return allContents;
    }
    private static Map<String, String> HtmlParseFromCert(String html)
    {
        /*this method with parse the html content and
        return Description,Impact,Solution,Vendor Information
        CVSS Metrics,References,Credit .....
        */


        Map<String,String> mapCont = new HashMap<String, String>();
        Document doc = Jsoup.parse(html);

        //select all the h3 elements with arte the ones that we care for
        Elements h3El = doc.select("h3");

        //get title of vulv
        Element h2el = doc.select("h2").first();
        mapCont.put("Title",h2el.text());

        for (int i = 0; i < h3El.size(); i++) {

            if(h3El.get(i).text().equals("Description"))
            {
                Element table = h3El.get(i).nextElementSibling();
                Element row = table.select("tr").first();
                Element td = row.select("td").first();

                mapCont.put("Description", StringEscapeUtils.escapeHtml(td.text()));

            }
            else if(h3El.get(i).text().equals("Impact"))
            {
                Element table = h3El.get(i).nextElementSibling();
                Element row = table.select("tr").first();
                Element td = row.select("td").first();

                mapCont.put("Impact", StringEscapeUtils.escapeHtml(td.text()));
            }
            else if(h3El.get(i).text().equals("Solution"))
            {
                Element table = h3El.get(i).nextElementSibling();
                Element row = table.select("tr").first();
                Element td = row.select("td").first();

                mapCont.put("Solution", StringEscapeUtils.escapeHtml(td.text()));

            }
            else if(h3El.get(i).text().contains("Vendor Information "))
            {

                String strToPut=" ";
                Element table = doc.getElementById("vendor-info2");

                if(table==null)
                {
                    Element table2 = h3El.get(i).nextElementSibling();
                    Elements tds = table2.getElementsByTag("td");

                    for (Element td : tds) {
                        strToPut += td.text()+"-";
                    }
                }
                else
                {
                    Elements ths = table.getElementsByTag("th");
                    for (Element th : ths) {
                        strToPut += th.text()+"|";
                    }
                    Elements tds = table.getElementsByTag("td");


                    for (Element td : tds) {
                        strToPut += td.text()+"-";
                    }

                }


                //System.out.println(strToPut);

                mapCont.put("Vendor Information",StringEscapeUtils.escapeHtml(strToPut));

            }
            else if(h3El.get(i).text().contains("CVSS Metrics "))
            {
                Element table = h3El.get(i).nextElementSibling();

                Element row1 = table.select("tr").get(1);
                Element td1 = row1.select("td").get(1);
                Element td1v = row1.select("td").get(2);

                Element row2 = table.select("tr").get(2);
                Element td2 = row2.select("td").get(1);
                Element td2v = row2.select("td").get(2);


                Element row3 = table.select("tr").get(3);
                Element td3 = row3.select("td").get(1);
                Element td3v = row3.select("td").get(2);


                String str = td1.text() +":" + td2.text() +":" +td3.text();
                String str2 = td1v.text() +"+" + td2v.text() +"+" +td3v.text();

                mapCont.put("CVSSscore",str);
                mapCont.put("CVSSvector",str2);
            }
            else if(h3El.get(i).text().equals("References"))
            {
                Element list = h3El.get(i).nextElementSibling();
                mapCont.put("References",StringEscapeUtils.escapeHtml(list.text()));
            }
            else if(h3El.get(i).text().equals("Credit"))
            {
                Element el = h3El.get(i).nextElementSibling();
                mapCont.put("Credit",StringEscapeUtils.escapeHtml(el.text()));
            }
            else if(h3El.get(i).text().equals("Other Information"))
            {
                Element list = h3El.get(i).nextElementSibling();
                Elements impElms = list.getElementsByTag("span");


                String strToReturn = "";

                for (int e = 0; e < impElms.size(); e++) {
                   if(!impElms.get(e).hasClass("field-title"))
                   {
                        strToReturn += impElms.get(e).text() +":";
                   }
                }

               // System.out.println(strToReturn);


                mapCont.put("Other Information",StringEscapeUtils.escapeHtml(strToReturn));

                return mapCont;
            }

            //rest to be completed

        }

        return null;
    }

    private static ArrayList<Map<String,String>>  getContFromRssNoHtml(String urlAdress, int size) {

        /*
            this method will take a rss URI as a parameter
            which contains only a string as a content
        */

        URL url;
        Iterator itEntries = null;
        try {
            //thetume ton browser Agent se browser-like gia na apofigume 403 errors
            System.setProperty("http.agent", "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0");
            url = new URL(urlAdress);
            HttpURLConnection httpcon = (HttpURLConnection) url.openConnection();
            httpcon.setRequestProperty("User-Agent",
                    "Mozilla/5.0 (Windows NT 5.1; rv:19.0) Gecko/20100101 Firefox/19.0");
            // Reading the feed
            SyndFeedInput input = new SyndFeedInput();

            //we allow doctype declarations used by some sources
            input.setAllowDoctypes(true);


            SyndFeed feed = input.build(new XmlReader(httpcon));


            if(feed.getEntries().size() <= size)
                    size=feed.getEntries().size();

            List entries = feed.getEntries().subList(0,size);
            itEntries = entries.iterator();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (FeedException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        //contAr has all the entries
        ArrayList<Map<String,String>> contAr = new ArrayList<Map<String, String>>();

        //contMap has all the entries contents
        Map<String,String> contMap = new HashMap<String, String>();
        contMap.put("URI",urlAdress);
        contAr.add(contMap);

        while (itEntries.hasNext()) {
            contMap = new HashMap<String, String>();
            SyndEntry entry = (SyndEntry) itEntries.next();
            //System.out.println(entry.getUri());
            contMap.put("Title",entry.getTitle());
            contMap.put("Link",entry.getLink());
            contMap.put("Description",entry.getDescription().getValue());

            contAr.add(contMap);
            System.out.println();
        }
        return contAr;
    }

    private static  ArrayList<String> getFeedContents(String urlString, int size)
    {
        ArrayList<String> htmlCont = new ArrayList<String>();
        SyndFeed feed = null;
        try{
            URL url = new URL(urlString);
            HttpURLConnection httpcon = (HttpURLConnection)url.openConnection();
            // Reading the feed
            SyndFeedInput input = new SyndFeedInput();
            feed = input.build(new XmlReader(httpcon));
        }catch (FeedException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }


        if(feed == null)
            return null;
        //parse rss feed content

        int toBreak = 0; //so we can stop on the user limit
        for (Iterator<?> entryIter = feed.getEntries().iterator(); entryIter.hasNext() && toBreak<size ;) {
            SyndEntry syndEntry = (SyndEntry) entryIter.next();
            //System.out.println(syndEntry.getDescription());
            if (syndEntry.getContents() != null) {
                for (Iterator<?> it = syndEntry.getContents().iterator(); it.hasNext();) {
                    SyndContent syndContent = (SyndContent) it.next();

                    if (syndContent != null) {
                        String value = syndContent.getValue();
                        htmlCont.add(value);
                    }
                }
            }
            toBreak++;
        }

        return htmlCont;
    }

}
