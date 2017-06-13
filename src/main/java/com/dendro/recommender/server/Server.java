package com.dendro.recommender.server;


import javax.ws.rs.GET;
import javax.ws.rs.MatrixParam;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import ContentManagment.*;
import Exceptions.UriNotFoundException;

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Map;


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
    public Response sayXMLHello(@MatrixParam("source") String source,@MatrixParam("limit") int limit)
    {
        String url = HelperMethods.getSourceFromName(source);

        if(url==null)
            return Response.status(200).entity("Source not found").build();

        ArrayList<Map<String,String>> parsedCont = ParsersFromRssClass.parseRssFeeds(url);
        ArrayList<Map<String,String>> cleanedCont = null;
        try {
            cleanedCont = CleanUpClass.cleanUp(parsedCont);

        } catch (UriNotFoundException e) {
            e.printStackTrace();
            Response.ResponseBuilder rs = Response.ok("uri not found");
            return rs.build();
        }

        String output = null;
        File file = null;
        Method method = null;
        ArrayList<String> fileNames;

        try {
            if(source.contains("cert"))
            {
                 method = StixProducer.class.getDeclaredMethod("cveGen", Map.class);
            }
            else if(source.contains("projecthoneypot"))
            {
                 method = StixProducer.class.getDeclaredMethod("produceForIp", Map.class);
            }
            else if(source.contains("malc0de"))
            {
                 method = StixProducer.class.getDeclaredMethod("produceForBadHost", Map.class);

            }
            else if(source.contains("malwaredomainlist"))
            {
                 method = StixProducer.class.getDeclaredMethod("produceForMalwareDomain", Map.class);
            }
            else if(source.contains("malekal"))
            {
                 method = StixProducer.class.getDeclaredMethod("produceForFileHash", Map.class);
            }
            else if(source.contains("threatexpert"))
            {
                 method = StixProducer.class.getDeclaredMethod("produceForThreat", Map.class);
            }
            else if(source.contains("malwaremustdie"))
            {
                method = StixProducer.class.getDeclaredMethod("produceForIp", Map.class);
            }

        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }


        fileNames = new ArrayList<String>();

        if(limit == 0 || limit >= cleanedCont.size())
            limit = cleanedCont.size();
        else
            limit++;

        for (int i = 1; i <limit; i++) {


            try {
                output = (String)method.invoke(null,cleanedCont.get(i));
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            } catch (InvocationTargetException e) {
                e.printStackTrace();
            }


            try {
                String userHome = System.getProperty("java.io.tmpdir");
                file = new File(userHome,"tmp.xml");
                FileWriter fileWriter = new FileWriter(file);
                fileWriter.write(output);
                fileWriter.flush();
                fileWriter.close();

                String newName = HelperMethods.getStixName(file.getPath());
                File file2 = new File(userHome,newName+".xml");



                java.nio.file.Path f = Paths.get(file.getAbsolutePath());

                java.nio.file.Path fs = Paths.get(file2.getAbsolutePath());

                try {
                    Files.move(f, fs, StandardCopyOption.REPLACE_EXISTING);
                    System.out.println("File was successfully renamed");
                    fileNames.add(file2.getAbsolutePath());
                    file.delete();
                } catch (IOException e)
                {
                    e.printStackTrace();
                    System.out.println("Error: unable to rename file");
                }


            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        File zipFile = HelperMethods.FilesToZip(fileNames,source+".zip");

        for (int i = 0; i < fileNames.size(); i++) {
            try {
                Files.deleteIfExists(Paths.get(fileNames.get(i)));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }




        Response.ResponseBuilder response = Response.ok((Object) zipFile);
        response.header("Content-Disposition",
                "attachment; filename=\" " +zipFile.getName() +"\"");
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