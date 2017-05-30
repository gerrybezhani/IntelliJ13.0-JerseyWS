import org.apache.commons.lang.StringUtils;
import org.mitre.cybox.common_2.*;
import org.mitre.cybox.common_2.ObjectFactory;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObservableCompositionType;
import org.mitre.cybox.cybox_2.OperatorTypeEnum;
import org.mitre.cybox.default_vocabularies_2.HashNameVocab10;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.objects.CategoryTypeEnum;
import org.mitre.cybox.objects.FileObjectType;
import org.mitre.cybox.objects.Hostname;
import org.mitre.stix.common_1.*;
import org.mitre.stix.common_1.DateTimeWithPrecisionType;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.courseofaction_1.CourseOfAction;
import org.mitre.stix.exploittarget_1.CVSSVectorType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.PotentialCOAsType;
import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.stix.indicator_2.Indicator;
import org.mitre.stix.stix_1.IndicatorsType;
import org.mitre.stix.stix_1.STIXHeaderType;
import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.stix_1.TTPsType;
import org.mitre.stix.ttp_1.*;
import org.mitre.stix.ttp_1.ExploitTargetsType;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Map;
import java.util.UUID;

/**
 * Created by gerry on 4/14/2017.
 */
public class StixProducer {

    //method for produces stix content for malware infected hosts
    public static void produceForBadHost(final Map<String,String> contents)
    {
        XMLGregorianCalendar now = HelperMethods.getTime();

        StringObjectPropertyType stringObjectPropertyType = (new ObjectFactory()).createStringObjectPropertyType().withValue(contents.get("IP"));
        Address addr = new Address()
                .withAddressValue(stringObjectPropertyType)
                .withCategory(CategoryTypeEnum.IPV_4_ADDR)
                .withIsSource(true);


        ObjectType objt = new ObjectType().withProperties(addr).withId(new QName("gerry.ptyxiaki.it.teithe", "observable-"
                + UUID.randomUUID().toString(), "gerry"));
        Observable obs = new Observable();

        obs.setObject(objt);

        FileObjectType fileObject = new FileObjectType()
                .withHashes(new HashListType(new ArrayList<HashType>() {
                    {
                        add(new HashType()
                                .withType(
                                        new HashNameVocab10()
                                                .withValue(contents.get("HASHTYPE")))
                                .withSimpleHashValue(
                                        new SimpleHashValueType()
                                                .withValue(contents.get("HASHVALUE"))));
                    }
                }));

        ObjectType obj = new ObjectType().withProperties(fileObject)
                .withId(new QName("gerry.ptyxiaki.it.teithe", "file-"
                        + UUID.randomUUID().toString(), "gerry"));

        Observable observable = new Observable().withId(new QName(
                "gerry.ptyxiaki.it.teithe", "observable-"
                + UUID.randomUUID().toString(), "gerry"));

        observable.setObject(obj);

        StringObjectPropertyType stringObjectPropertyTypeHost = (new ObjectFactory()).createStringObjectPropertyType().withValue(contents.get("HOST"));

        ObjectType obj2 = new ObjectType().withProperties(new Hostname().withHostnameValue(stringObjectPropertyTypeHost));
        Observable observable2 = new Observable().withId(new QName(
                "gerry.ptyxiaki.it.teithe", "observable-"
                + UUID.randomUUID().toString(), "gerry"));

        observable2.setObject(obj2);

        //observable for asn
        StringObjectPropertyType stringObjectPropertyTypeAsn = (new ObjectFactory()).createStringObjectPropertyType().withValue(contents.get("ASN"));

        ObjectType objAsn = new ObjectType().withProperties(new Address().withCategory(CategoryTypeEnum.ASN)
        .withAddressValue(stringObjectPropertyTypeAsn));
        Observable observableAsn = new Observable().withId(new QName(
                "gerry.ptyxiaki.it.teithe", "observable-"
                + UUID.randomUUID().toString(), "gerry"));

        observable2.setObject(objAsn);

        //observable for source country


        ObjectType objCountry = new ObjectType().withLocation(new LocationType().withName(contents.get("COUNTRY")));
        Observable observableCountry = new Observable().withId(new QName(
                "gerry.ptyxiaki.it.teithe", "observable-"
                + UUID.randomUUID().toString(), "gerry"));

        observableCountry.setObject(objCountry);

        //Arraylist for all the observables so we can create an observable composition
        ArrayList<Observable> obsList = new ArrayList<Observable>();
        obsList.add(obs);
        obsList.add(observable);
        obsList.add(observable2);
        obsList.add(observableAsn);
        obsList.add(observableCountry);




        ObservableCompositionType observableCompositionType = new ObservableCompositionType(obsList, OperatorTypeEnum.AND);



        final Indicator indicator = new Indicator()
                .withId(new QName("gerry.ptyxiaki.it.teithe", "indicator-"
                        + UUID.randomUUID().toString(), "gerry"))
                .withTimestamp(now)
                .withTitle("Malware infected host")
                .withObservable(new Observable().withObservableComposition(observableCompositionType));
        IndicatorsType indicators = new IndicatorsType(
                new ArrayList<IndicatorBaseType>() {
                    {
                        add(indicator);
                    }
                });

        STIXHeaderType stixHeader = new STIXHeaderType()
                .withDescriptions(new StructuredTextType()
                        .withValue("Malware infected host"));

        STIXPackage stixPackage = new STIXPackage()
                .withSTIXHeader(stixHeader)
                .withVersion("1.2")
                .withTimestamp(now)
                .withId(new QName("gerry.ptyxiaki.it.teithe", "package-"
                        + UUID.randomUUID().toString(), "gerry"))
                .withIndicators(indicators);


        System.out.println(stixPackage.toXMLString(true));

        System.out.println(StringUtils.repeat("-", 120));

        System.out.println("Validates: " + stixPackage.validate());

    }

    public static void produceForMalwareDomain(final Map<String,String> contents) {
        XMLGregorianCalendar now = HelperMethods.getTime();

        StringObjectPropertyType stringObjectPropertyType = (new ObjectFactory()).createStringObjectPropertyType().withValue(contents.get("IP"));
        Address addr = new Address()
                .withAddressValue(stringObjectPropertyType)
                .withCategory(CategoryTypeEnum.IPV_4_ADDR)
                .withIsSource(true);


        ObjectType objt = new ObjectType().withProperties(addr).withId(new QName("gerry.ptyxiaki.it.teithe", "observable-"
                + UUID.randomUUID().toString(), "gerry"));
        Observable obs = new Observable();

        obs.setObject(objt);


        StringObjectPropertyType stringObjectPropertyTypeHost = (new ObjectFactory()).createStringObjectPropertyType().withValue(contents.get("Host"));

        ObjectType obj2 = new ObjectType().withProperties(new Hostname().withHostnameValue(stringObjectPropertyTypeHost));
        Observable observable2 = new Observable().withId(new QName(
                "gerry.ptyxiaki.it.teithe", "observable-"
                + UUID.randomUUID().toString(), "gerry"));

        observable2.setObject(obj2);

        //observable for asn
        StringObjectPropertyType stringObjectPropertyTypeAsn = (new ObjectFactory()).createStringObjectPropertyType().withValue(contents.get("ASN"));

        ObjectType objAsn = new ObjectType().withProperties(new Address().withCategory(CategoryTypeEnum.ASN)
                .withAddressValue(stringObjectPropertyTypeAsn));
        Observable observableAsn = new Observable().withId(new QName(
                "gerry.ptyxiaki.it.teithe", "observable-"
                + UUID.randomUUID().toString(), "gerry"));

        observable2.setObject(objAsn);

        //observable for source country


        ObjectType objCountry = new ObjectType().withLocation(new LocationType().withName(contents.get("Country")));
        Observable observableCountry = new Observable().withId(new QName(
                "gerry.ptyxiaki.it.teithe", "observable-"
                + UUID.randomUUID().toString(), "gerry"));

        observableCountry.setObject(objCountry);

        //Arraylist for all the observables so we can create an observable composition
        ArrayList<Observable> obsList = new ArrayList<Observable>();
        obsList.add(obs);
        obsList.add(observable2);
        obsList.add(observableAsn);
        obsList.add(observableCountry);


        ObservableCompositionType observableCompositionType = new ObservableCompositionType(obsList, OperatorTypeEnum.AND);


        final Indicator indicator = new Indicator()
                .withId(new QName("gerry.ptyxiaki.it.teithe", "indicator-"
                        + UUID.randomUUID().toString(), "gerry"))
                .withTimestamp(now)
                .withTitle("Malware infected host")
                .withObservable(new Observable().withObservableComposition(observableCompositionType));
        IndicatorsType indicators = new IndicatorsType(
                new ArrayList<IndicatorBaseType>() {
                    {
                        add(indicator);
                    }
                });

        //TTP for the description
        String threat = contents.get("Description");
        MalwareInstanceType malwareInstanceType = new MalwareInstanceType().withId(new QName("gerry.ptyxiaki.it.teithe", "observable-"
                + UUID.randomUUID().toString(), "gerry"))
                .withTitle(threat);

        MalwareType malwareType = new MalwareType().withMalwareInstances(malwareInstanceType);

        TTP ttp = new TTP()
                .withTitle("Tactics ")
                .withShortDescriptions(new StructuredTextType().withValue(threat))
                .withBehavior(new BehaviorType().withMalware(malwareType));


        STIXHeaderType stixHeader = new STIXHeaderType()
                .withDescriptions(new StructuredTextType()
                        .withValue("Malware infected domain"));

        STIXPackage stixPackage = new STIXPackage()
                .withSTIXHeader(stixHeader)
                .withVersion("1.2")
                .withTimestamp(now)
                .withId(new QName("gerry.ptyxiaki.it.teithe", "package-"
                        + UUID.randomUUID().toString(), "gerry"))
                .withIndicators(indicators)
                .withTTPs(new TTPsType().withTTPS(ttp));



        System.out.println(stixPackage.toXMLString(true));

        System.out.println(StringUtils.repeat("-", 120));

        System.out.println("Validates: " + stixPackage.validate());
    }

    //Method for producing stix from malware domain list

    //method that produces stix contnet for threats
    public static void produceForThreat(String threat)
    {
        XMLGregorianCalendar now = HelperMethods.getTime();

        MalwareInstanceType malwareInstanceType = new MalwareInstanceType().withId(new QName("gerry.ptyxiaki.it.teithe", "observable-"
                + UUID.randomUUID().toString(), "gerry"))
                .withTitle(threat);

        MalwareType malwareType = new MalwareType().withMalwareInstances(malwareInstanceType);

        TTP ttp = new TTP()
                .withTitle("Malware/Adaware")
                .withShortDescriptions(new StructuredTextType().withValue("badware "+threat))
                .withBehavior(new BehaviorType().withMalware(malwareType));

        STIXHeaderType stixHeader = new STIXHeaderType()
                .withDescriptions(new StructuredTextType()
                        .withValue("Malware/adaware"));

        STIXPackage stixPackage = new STIXPackage()
                .withSTIXHeader(stixHeader)
                .withVersion("1.2")
                .withTimestamp(now)
                .withId(new QName("gerry.ptyxiaki.it.teithe", "package-"
                        + UUID.randomUUID().toString(), "gerry"))
                .withTTPs(new TTPsType().withTTPS(ttp));


        System.out.println(stixPackage.toXMLString(true));

        System.out.println(StringUtils.repeat("-", 120));

        System.out.println("Validates: " + stixPackage.validate());

    }


    //method that produces stix content for hashes of files

    public static void produceForFileHash(final Map<String,String> content)
    {
        XMLGregorianCalendar now = HelperMethods.getTime();
        FileObjectType fileObject = new FileObjectType()
                .withHashes(new HashListType(new ArrayList<HashType>() {
                    {
                        add(new HashType()
                                .withType(
                                        new HashNameVocab10()
                                                .withValue(content.get("HASHTYPE")))
                                .withSimpleHashValue(
                                        new SimpleHashValueType()
                                                .withValue(content.get("HASHVALUE"))));
                    }
                }));

        ObjectType obj = new ObjectType().withProperties(fileObject)
                .withId(new QName("gerry.ptyxiaki.it.teithe", "file-"
                        + UUID.randomUUID().toString(), "gerry"));

        Observable observable = new Observable().withId(new QName(
                "gerry.ptyxiaki.it.teithe", "observable-"
                + UUID.randomUUID().toString(), "gerry"));

        observable.setObject(obj);

        IdentityType identity = new IdentityType()
                .withName("The MITRE Corporation");

        ReferencesType referencesType = new ReferencesType().withReferences(content.get("reference"));

        InformationSourceType producer = new InformationSourceType()
                .withIdentity(identity)
                .withTime(
                        new TimeType()
                                .withProducedTime(new org.mitre.cybox.common_2.DateTimeWithPrecisionType(now,null)))
                .withReferences(referencesType);

        final Indicator indicator = new Indicator()
                .withId(new QName("gerry.ptyxiaki.it.teithe", "indicator-"
                        + UUID.randomUUID().toString(), "gerry"))
                .withTimestamp(now)
                .withTitle("Malicious MD5 file hash")
                .withDescriptions(
                        new StructuredTextType()
                                .withValue("An indicator containing a File observable with an associated hash"))
                .withObservable(observable).withProducer(producer);

        IndicatorsType indicators = new IndicatorsType(
                new ArrayList<IndicatorBaseType>() {
                    {
                        add(indicator);
                    }
                });

        STIXHeaderType stixHeader = new STIXHeaderType()
                .withDescriptions(new StructuredTextType()
                        .withValue("Malicious file hash"));

        STIXPackage stixPackage = new STIXPackage()
                .withSTIXHeader(stixHeader)
                .withIndicators(indicators)
                .withVersion("1.2")
                .withTimestamp(now)
                .withId(new QName("gerry.ptyxiaki.it.teithe", "package-"
                        + UUID.randomUUID().toString(), "gerry"));

        System.out.println(stixPackage.toXMLString(true));

        System.out.println(StringUtils.repeat("-", 120));

        System.out.println("Validates: " + stixPackage.validate());


    }

    public static void produce(String IP,String type) {

        XMLGregorianCalendar now = HelperMethods.getTime();

        StringObjectPropertyType stringObjectPropertyType = (new ObjectFactory()).createStringObjectPropertyType().withValue(IP);
        Address addr = new Address()
                .withAddressValue(stringObjectPropertyType)
                .withCategory(CategoryTypeEnum.IPV_4_ADDR)
                .withIsSource(true);


        ObjectType objt = new ObjectType().withProperties(addr).withId(new QName("gerry.ptyxiaki.it.teithe", "observable-"
                + UUID.randomUUID().toString(), "gerry"));
        Observable obs = new Observable();

        obs.setObject(objt);
        final Indicator indicator = new Indicator()
                .withId(new QName(UUID.randomUUID().toString()))
                .withTimestamp(now)
                .withTitle(type)
                .withDescriptions(
                        new StructuredTextType()
                                .withValue("Ip Watchlist")
                ).withObservable(obs);

        IndicatorsType indicators = new IndicatorsType(
                new ArrayList<IndicatorBaseType>() {
                    {
                        add(indicator);
                    }
                });

        STIXHeaderType stixHeader = new STIXHeaderType()
                .withDescriptions(new StructuredTextType()
                        .withValue("IP WATCHLIST"));

        STIXPackage stixPackage = new STIXPackage()
                .withSTIXHeader(stixHeader)
                .withIndicators(indicators)
                .withVersion("1.2")
                .withTimestamp(now)
                .withId(new QName("gerry.ptyxiaki.it.teithe", "package-"
                        + UUID.randomUUID().toString(), "gerry"));

        System.out.println(stixPackage.toXMLString(true));

        System.out.println(StringUtils.repeat("-", 120));

        System.out.println("Validates: " + stixPackage.validate());
    }

    public static void cveGen(Map<String,String> content)
    {
        //cleaning up the other info to het cve id and dates
        String otherInfoStr = content.get("Other Information");
        String[] otherInfoTable = StringUtils.split(otherInfoStr,":");



        DateTimeWithPrecisionType dt = new DateTimeWithPrecisionType();

        ExploitTarget exploitTarget = new ExploitTarget();
        VulnerabilityType vulnerabilityType = new VulnerabilityType().
                withTitle(content.get("Title"))
                .withDescriptions(new StructuredTextType().withValue(content.get("Description")))
                .withShortDescriptions(new StructuredTextType().withValue(content.get("Overview")))
                .withCVEID(otherInfoTable[0])
                .withReferences(new ReferencesType().withReferences(content.get("References")))
                .withPublishedDateTime(new DateTimeWithPrecisionType().withValue(HelperMethods.getDateFromString(otherInfoTable[2])));


        VictimTargetingType victimTargetingType = new VictimTargetingType().
                withIdentity(new IdentityType().withName(content.get("Vendor Information")));

        CVSSVectorType cvssVectorType = new CVSSVectorType()
                .withBaseScore(StringUtils.split(content.get("CVSSscore"),":")[0])
                .withTemporalScore(StringUtils.split(content.get("CVSSscore"),":")[1])
                .withEnvironmentalScore(StringUtils.split(content.get("CVSSscore"),":")[2])
                .withBaseVector(StringUtils.split(content.get("CVSSvector"),"+")[0])
                .withTemporalVector(StringUtils.split(content.get("CVSSvector"),"+")[1])
                .withEnvironmentalVector(StringUtils.split(content.get("CVSSvector"),"+")[2]);

        vulnerabilityType.withCVSSScore(cvssVectorType);

        InformationSourceType informationSourceType = new InformationSourceType()
                .withDescriptions(new StructuredTextType().withValue(content.get("Credit")));

        exploitTarget.withInformationSource(informationSourceType);

        exploitTarget.withVulnerabilities(vulnerabilityType);

        CourseOfActionBaseType courseOfActionBaseType = new CourseOfAction()
                .withDescriptions(new StructuredTextType().withValue(content.get("Solution")));

        RelatedCourseOfActionType relatedCourseOfActionType = new RelatedCourseOfActionType()
                .withCourseOfAction(courseOfActionBaseType);

        exploitTarget.withPotentialCOAs(
                new PotentialCOAsType().withPotentialCOAs(relatedCourseOfActionType)
        );






        RelatedExploitTargetType exploitTargetType = new RelatedExploitTargetType()
                .withExploitTarget(exploitTarget);



        AttackPatternType attackPatternType = new AttackPatternType().withDescriptions(new StructuredTextType().withValue(content.get("Impact")));

        TTP ttp = new TTP()
                .withBehavior(new BehaviorType()
                        .withAttackPatterns(new AttackPatternsType().withAttackPatterns(attackPatternType)))
                .withExploitTargets(new ExploitTargetsType().withExploitTargets(exploitTargetType))
                .withVictimTargeting(victimTargetingType);


        XMLGregorianCalendar now = HelperMethods.getTime();

        STIXHeaderType stixHeader = new STIXHeaderType()
                .withDescriptions(new StructuredTextType()
                        .withValue("CVE exploit"));

        STIXPackage stixPackage = new STIXPackage()
                .withSTIXHeader(stixHeader)
                .withTTPs(new TTPsType().withTTPS(ttp))
                .withVersion("1.2")
                .withTimestamp(now)
                .withId(new QName("gerry.ptyxiaki.it.teithe", "package-"
                        + UUID.randomUUID().toString(), "gerry"));

        System.out.println(stixPackage.toXMLString(true));

        System.out.println(StringUtils.repeat("-", 120));


        System.out.println("Validates: " + stixPackage.validate());
    }

}
