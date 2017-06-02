package com.dendro.recommender.server;


import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import ContentManagment.*;
import Exceptions.UriNotFoundException;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static ContentManagment.AdressesClass.getUrls;

// Plain old Java Object it does not extend as class or implements
// an interface

// The class registers its methods for the HTTP GET request using the @GET annotation.
// Using the @Produces annotation, it defines that it can deliver several MIME types,
// text, XML and HTML.

// The browser requests per default the HTML MIME type.

//Sets the path to base URL + /hello
@Path("/stix")
public class Server {


    // This method is called if TEXT_PLAIN is request
    @GET
    @Path("/ShowSources")
    @Produces(MediaType.TEXT_HTML)
    public Response ShowSources()
    {
        ArrayList<String> urls = AdressesClass.getUrls();
        String output="";
       for(String temp : urls)
       {
           output+=temp+"<br>";
       }
        return Response.status(200).entity(output).build();

    }



    // This method is called if XML is request
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public Response sayXMLHello()
    {
        ArrayList<Map<String,String>> parsedCont = ParsersFromRssClass.parseRssFeeds("http://www.kb.cert.org/vulfeed");
        ArrayList<Map<String,String>> cleanedCont = null;
        try {
            cleanedCont = CleanUpClass.cleanUp(parsedCont);

        } catch (UriNotFoundException e) {
            e.printStackTrace();
            Response.ResponseBuilder rs = Response.ok("uri not found");
            return rs.build();
        }

        String output;
        File file = null;
        for (int i = 1; i < cleanedCont.size(); i++) {
            output=StixProducer.cveGen(cleanedCont.get(i));

            file = null;
            try {
                file = new File("tmp/stix.xml");
                FileWriter fileWriter = new FileWriter(file);
                fileWriter.write(output);
                fileWriter.flush();
                fileWriter.close();

                String newName = HelperMethods.getStixName(file.getPath());
                File file2 = new File("tmp/"+newName+".xml");

                java.nio.file.Path f = Paths.get(file.getAbsolutePath());

                java.nio.file.Path fs = Paths.get(file2.getAbsolutePath());

                try {
                    Files.move(f, fs, StandardCopyOption.REPLACE_EXISTING);
                    System.out.println("File was successfully renamed");
                } catch (IOException e)
                {
                    e.printStackTrace();
                    System.out.println("Error: unable to rename file");
                }


            } catch (IOException e) {
                e.printStackTrace();
            }
        }



        Response.ResponseBuilder response = Response.ok((Object) file);
        response.header("Content-Disposition",
                "attachment; filename=\"stix.xml\"");
        return response.build();

    }






    // This method is called if HTML is request
    @GET
    @Path("/test")
    @Produces(MediaType.TEXT_HTML)
    public String sayHtmlHello() {
        return "<html> " + "<title>" + "Hello Jersey" + "</title>"
                + "<body><h1>" + "Hello Jersey" + "</body></h1>" + "</html> ";
    }


}