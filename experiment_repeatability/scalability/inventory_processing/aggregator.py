import math

class Aggregator:
    # Constructor
    def __init__(self) -> None:
        pass


    
    # CVSS tokenizer
    def tokenize_cvss(cvss3_string):
        cvss_str = dict()
        
        av = cvss3_string[:cvss3_string.find("/")]
        av = av.replace("AV:","")
        cvss3_string = cvss3_string[cvss3_string.find("/")+1:]

        ac = cvss3_string[:cvss3_string.find("/")]
        ac = ac.replace("AC:","")
        cvss3_string = cvss3_string[cvss3_string.find("/")+1:]

        pr = cvss3_string[:cvss3_string.find("/")]
        pr = pr.replace("PR:","")
        cvss3_string = cvss3_string[cvss3_string.find("/")+1:]

        ui = cvss3_string[:cvss3_string.find("/")]
        ui = ui.replace("UI:","")
        cvss3_string = cvss3_string[cvss3_string.find("/")+1:]

        s = cvss3_string[:cvss3_string.find("/")]
        s = s.replace("S:","")
        cvss3_string = cvss3_string[cvss3_string.find("/")+1:]

        c = cvss3_string[:cvss3_string.find("/")]
        c = c.replace("C:","")
        cvss3_string = cvss3_string[cvss3_string.find("/")+1:]

        i = cvss3_string[:cvss3_string.find("/")]
        i = i.replace("I:","")
        cvss3_string = cvss3_string[cvss3_string.find("/")+1:]

        a = cvss3_string
        a = a.replace("A:","")

        cvss_str["AV"] = av
        cvss_str["AC"] = ac
        cvss_str["PR"] = pr
        cvss_str["UI"] = ui
        cvss_str["S"] = s
        cvss_str["C"] = c
        cvss_str["I"] = i
        cvss_str["A"] = a

        return cvss_str



    # CVSS converter
    def convert_cvss(cvss2):
        old_string = cvss2

        old_av = old_string[:old_string.find("/")]
        old_av = old_av.replace("AV:","")
        old_string = old_string[old_string.find("/")+1:]

        old_ac = old_string[:old_string.find("/")]
        old_ac = old_ac.replace("AC:","")
        old_string = old_string[old_string.find("/")+1:]

        old_au = old_string[:old_string.find("/")]
        old_au = old_au.replace("Au:","")
        old_string = old_string[old_string.find("/")+1:]

        old_c = old_string[:old_string.find("/")]
        old_c = old_av.replace("C:","")
        old_string = old_string[old_string.find("/")+1:]

        old_i = old_string[:old_string.find("/")]
        old_i = old_av.replace("I:","")
        old_string = old_string[old_string.find("/")+1:]

        old_a = old_string
        old_a = old_av.replace("A:","")

        new_av = "N"
        if old_av == "A":
            new_av = "A"
        if old_av == "L":
            new_av = "L"

        new_ac = "H"
        new_ui = "R"
        if old_ac == "M":
            new_ac = "H"
            new_ui = "N"
        if old_ac == "L":
            new_ac = "L"
            new_ui = "N"

        new_pr = "N"
        if old_au == "S":
            new_pr = "L"
        if old_au == "M":
            new_pr = "H"

        new_c = "N"
        if old_c == "P":
            new_c = "L"
        if old_c == "C":
            new_c = "H"

        new_i = "N"
        if old_i == "P":
            new_i = "L"
        if old_i == "C":
            new_i = "H"

        new_a = "N"
        if old_a == "P":
            new_a = "L"
        if old_a == "C":
            new_a = "H"

        new_s = "U"
        if new_c == "H" and new_i == "H" and new_a == "H":
            new_s = "C"

        new_string = "AV:"+new_av+"/AC:"+new_ac+"/PR:"+new_pr+"/UI:"+new_ui+"/S:"+new_s+"/C:"+new_c+"/I:"+new_i+"/A:"+new_a
        return new_string



    # Pre and post calculator
    def compute_pre_post(cvss3):
        pre_condition = "USER"
        post_condition = "NONE"

        tokenizedv3 = Aggregator.tokenize_cvss(cvss3)
        if (tokenizedv3["AV"] == "N") and (tokenizedv3["PR"] == "N"):
            # Network

            # Post condition
            if (tokenizedv3["S"] == "U"):
                # USER candidate
                if ((tokenizedv3["C"] == "H") or (tokenizedv3["C"] == "L")) and ((tokenizedv3["I"] == "H") or (tokenizedv3["I"] == "L")) and ((tokenizedv3["A"] == "H") or (tokenizedv3["A"] == "L")):
                    post_condition = "USER"
            else:
                # ROOT candidate
                if (tokenizedv3["C"] == "H") and (tokenizedv3["I"] == "H") and (tokenizedv3["A"] == "H"):
                    post_condition = "ROOT"

        else:
            # Local

            # Pre condition
            if (tokenizedv3["PR"] == "N"):
                pre_condition = "NONE"
            elif (tokenizedv3["PR"] == "L"):
                pre_condition = "USER"
            else:
                pre_condition = "ROOT"

            # Post condition
            if (tokenizedv3["S"] == "U"):
                # USER candidate
                if ((tokenizedv3["C"] == "H") or (tokenizedv3["C"] == "L")) and ((tokenizedv3["I"] == "H") or (tokenizedv3["I"] == "L")) and ((tokenizedv3["A"] == "H") or (tokenizedv3["A"] == "L")):
                    post_condition = "USER"
            else:
                # ROOT candidate
                if (tokenizedv3["C"] == "H") and (tokenizedv3["I"] == "H") and (tokenizedv3["A"] == "H"):
                    post_condition = "ROOT"

        return pre_condition,post_condition 



    def compute_max_cvss(cvss3_list):
        max_cvss = "AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"
        tokenized_max_cvss = Aggregator.tokenize_cvss(max_cvss)

        for cvss3 in cvss3_list:
            tokenized_cvss = Aggregator.tokenize_cvss(cvss3)

            # AV
            if (tokenized_cvss["AV"] == "N"): tokenized_max_cvss["AV"] = "N"
            if (tokenized_cvss["AV"] == "A") and ((tokenized_max_cvss["AV"] == "L") or (tokenized_max_cvss["AV"] == "P")): tokenized_max_cvss["AV"] = "A"
            if (tokenized_cvss["AV"] == "L") and (tokenized_max_cvss["AV"] == "P"): tokenized_max_cvss["AV"] = "L"

            # AC
            if (tokenized_cvss["AC"] == "L"): tokenized_max_cvss["AC"] = "L"

            # PR
            if (tokenized_cvss["PR"] == "N"): tokenized_max_cvss["PR"] = "N"
            if (tokenized_cvss["PR"] == "L") and (tokenized_max_cvss["PR"] == "H"): tokenized_max_cvss["PR"] = "L"

            # UI
            if (tokenized_cvss["UI"] == "N"): tokenized_max_cvss["UI"] = "N"

            # S
            if (tokenized_cvss["S"] == "C"): tokenized_max_cvss["S"] = "C"

            # C
            if (tokenized_cvss["C"] == "H"): tokenized_max_cvss["C"] = "H"
            if (tokenized_cvss["C"] == "L") and (tokenized_max_cvss["C"] == "N"): tokenized_max_cvss["C"] = "L"

            # I
            if (tokenized_cvss["I"] == "H"): tokenized_max_cvss["I"] = "H"
            if (tokenized_cvss["I"] == "L") and (tokenized_max_cvss["I"] == "N"): tokenized_max_cvss["I"] = "L"

            # A
            if (tokenized_cvss["A"] == "H"): tokenized_max_cvss["A"] = "H"
            if (tokenized_cvss["A"] == "L") and (tokenized_max_cvss["A"] == "N"): tokenized_max_cvss["A"] = "L"

        max_cvss = "AV:"+tokenized_max_cvss["AV"]+"/AC:"+tokenized_max_cvss["AC"]+"/PR:"+tokenized_max_cvss["PR"]+"/UI:"+tokenized_max_cvss["UI"]+"/S:"+tokenized_max_cvss["S"]+"/C:"+tokenized_max_cvss["C"]+"/I:"+tokenized_max_cvss["I"]+"/A:"+tokenized_max_cvss["A"]
        return max_cvss
    


    # Package CVSS
    def package_cvss(cvss3):
        packaged_cvss = dict()
        packaged_cvss["string"] = cvss3
        packaged_cvss["base"] = 0
        packaged_cvss["impact"] = 0
        packaged_cvss["exploitability"] = 0

        # Score calculation
        tokenized_cvss = Aggregator.tokenize_cvss(cvss3)

        iconf = 0
        if tokenized_cvss["C"] == "L": iconf = 0.22
        elif tokenized_cvss["C"] == "H": iconf = 0.56
        iinteg = 0
        if tokenized_cvss["I"] == "L": iinteg = 0.22
        elif tokenized_cvss["I"] == "H": iinteg = 0.56
        iavail = 0
        if tokenized_cvss["A"] == "L": iavail = 0.22
        elif tokenized_cvss["A"] == "H": iavail = 0.56

        isc_base = (1-((1-iconf)*(1-iinteg)*(1-iavail)))
        if tokenized_cvss["S"] == "U": packaged_cvss["impact"] = 6.42*isc_base
        else: packaged_cvss["impact"] = 7.52*(isc_base-0.029)-3.25*math.pow((isc_base-0.02),15)


        av = 0.2
        if tokenized_cvss["AV"] == "N": av = 0.85
        elif tokenized_cvss["AV"] == "A": av = 0.62
        elif tokenized_cvss["AV"] == "L": av = 0.55
        ac = 0.44
        if tokenized_cvss["AC"] == "L": ac = 0.77
        pr = 0.85
        if tokenized_cvss["PR"] == "L": 
            if tokenized_cvss["S"] == "U": pr = 0.62
            else: pr = 0.68
        elif tokenized_cvss["PR"] == "H": 
            if tokenized_cvss["S"] == "U": pr = 0.27
            else: pr = 0.5
        ui = 0.62
        if tokenized_cvss["UI"] == "N": ui = 0.85

        packaged_cvss["exploitability"] = 8.22*av*ac*pr*ui


        packaged_cvss["base"] = 0
        if packaged_cvss["impact"] > 0:
            if tokenized_cvss["S"] == "U": packaged_cvss["base"] = math.ceil(min(packaged_cvss["impact"]+packaged_cvss["exploitability"],10)*10)/10
            else: packaged_cvss["base"] = math.ceil(min(1.08*(packaged_cvss["impact"]+packaged_cvss["exploitability"]),10)*10)/10


        return packaged_cvss



    # Grab CVSS from NVD
    def grab_cvss_from_cve(cve_str):
        cvssv3 = "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        if ("cvssMetricV31" in cve_str["metrics"]):
            for metric in cve_str["metrics"]["cvssMetricV31"]:
                if metric["type"] == "Primary":
                    cvssv3 = metric["cvssData"]["vectorString"].replace("CVSS:3.1/","")
        elif ("cvssMetricV30" in cve_str["metrics"]):
            for metric in cve_str["metrics"]["cvssMetricV30"]:
                if metric["type"] == "Primary":
                    cvssv3 = metric["cvssData"]["vectorString"].replace("CVSS:3.0/","")
        elif ("cvssMetricV2" in cve_str["metrics"]):
            for metric in cve_str["metrics"]["cvssMetricV2"]:
                if metric["type"] == "Primary":
                    cvssv3 = Aggregator.convert_cvss(metric["cvssData"]["vectorString"])
        return cvssv3



    # Aggregation by level
    # Level 0, don't do anything
    def no_aggregation(vulnerability_list):
        aggregation_class_to_vulnerabilities = dict()

        for cve_str in vulnerability_list:
            if cve_str["id"] not in aggregation_class_to_vulnerabilities:
                aggregation_class_to_vulnerabilities[cve_str["id"]] = dict()
            
            aggregation_class_to_vulnerabilities[cve_str["id"]]["vulnerability_id_list"] = list()
            aggregation_class_to_vulnerabilities[cve_str["id"]]["vulnerability_id_list"].append(cve_str["id"])

            cvssv3 = Aggregator.grab_cvss_from_cve(cve_str)
            
            aggregation_class_to_vulnerabilities[cve_str["id"]]["pre_condition"], aggregation_class_to_vulnerabilities[cve_str["id"]]["post_condition"] = Aggregator.compute_pre_post(cvssv3)
            aggregation_class_to_vulnerabilities[cve_str["id"]]["cvss_metrics"] = Aggregator.package_cvss(cvssv3)

        return aggregation_class_to_vulnerabilities


    # Level 1, max accuracy
    def max_accuracy_aggregation(vulnerability_list):
        aggregation_class_to_vulnerabilities = dict()

        for cve_str in vulnerability_list:

            # Merge all CVSS definitions into one
            bucket_identifier = ""
            cvssv3 = Aggregator.grab_cvss_from_cve(cve_str)
            bucket_identifier = cvssv3

            if bucket_identifier not in aggregation_class_to_vulnerabilities:
                aggregation_class_to_vulnerabilities[bucket_identifier] = dict()
                aggregation_class_to_vulnerabilities[bucket_identifier]["vulnerability_id_list"] = list()

            aggregation_class_to_vulnerabilities[bucket_identifier]["vulnerability_id_list"].append(cve_str["id"])


        # Pre and post
        # CVSS
        for bucket_identifier in aggregation_class_to_vulnerabilities:
            aggregation_class_to_vulnerabilities[bucket_identifier]["pre_condition"], aggregation_class_to_vulnerabilities[bucket_identifier]["post_condition"] = Aggregator.compute_pre_post(bucket_identifier)
            aggregation_class_to_vulnerabilities[bucket_identifier]["cvss_metrics"] = Aggregator.package_cvss(bucket_identifier)

        return aggregation_class_to_vulnerabilities


    # Level 2, same likelihood
    def same_likelihood_aggregation(vulnerability_list):
        aggregation_class_to_vulnerabilities = dict()
        aggregation_class_to_cvssv3 = dict()

        for cve_str in vulnerability_list:

            # Merge all CVSS definitions into one
            bucket_identifier = ""
            cvssv3 = Aggregator.grab_cvss_from_cve(cve_str)
            bucket_identifier = cvssv3

            # Cut the bucket_identifier to only likelihood metrics
            tokenized_bucket = Aggregator.tokenize_cvss(bucket_identifier)
            reference_cvss = bucket_identifier
            bucket_identifier = tokenized_bucket["AV"]+":"+tokenized_bucket["AC"]+":"+tokenized_bucket["PR"]+":"+tokenized_bucket["UI"]#+":"+tokenized_bucket["S"]

            if bucket_identifier not in aggregation_class_to_vulnerabilities:
                aggregation_class_to_vulnerabilities[bucket_identifier] = dict()
                aggregation_class_to_vulnerabilities[bucket_identifier]["vulnerability_id_list"] = list()
                aggregation_class_to_cvssv3[bucket_identifier] = list()

            aggregation_class_to_vulnerabilities[bucket_identifier]["vulnerability_id_list"].append(cve_str["id"])
            aggregation_class_to_cvssv3[bucket_identifier].append(reference_cvss)


        # Pre and post
        # CVSS
        for bucket_identifier in aggregation_class_to_vulnerabilities:
            max_cvssv3 = Aggregator.compute_max_cvss(aggregation_class_to_cvssv3[bucket_identifier])
            aggregation_class_to_vulnerabilities[bucket_identifier]["pre_condition"], aggregation_class_to_vulnerabilities[bucket_identifier]["post_condition"] = Aggregator.compute_pre_post(max_cvssv3)
            aggregation_class_to_vulnerabilities[bucket_identifier]["cvss_metrics"] = Aggregator.package_cvss(max_cvssv3)

        return aggregation_class_to_vulnerabilities


    # Level 3, max compression
    def max_compression_aggregation(vulnerability_list):
        aggregation_class_to_vulnerabilities = dict()
        aggregation_class_to_vulnerabilities["unique"] = dict()
        aggregation_class_to_vulnerabilities["unique"]["vulnerability_id_list"] = list()
        for cve_str in vulnerability_list:
            aggregation_class_to_vulnerabilities["unique"]["vulnerability_id_list"].append(cve_str["id"])

        # Pre and post
        cvssv3_list = list()
        for cve_str in vulnerability_list:
            cvssv3 = Aggregator.grab_cvss_from_cve(cve_str)
            cvssv3_list.append(cvssv3)
        
        max_cvssv3 = Aggregator.compute_max_cvss(cvssv3_list)
        aggregation_class_to_vulnerabilities["unique"]["pre_condition"], aggregation_class_to_vulnerabilities["unique"]["post_condition"] = Aggregator.compute_pre_post(max_cvssv3)
        aggregation_class_to_vulnerabilities["unique"]["cvss_metrics"] = Aggregator.package_cvss(max_cvssv3)

        return aggregation_class_to_vulnerabilities



    # Main function
    def perform(level,vulnerability_list):
        # print("Performing aggregation operation [",level,"]")
        
        # Initialize return structure
        aggregation_class_to_vulnerabilities = dict()
        
        # Bucket vulnerabilities according to level
        if level == 0:
            # level 0, don't do anything
            aggregation_class_to_vulnerabilities = Aggregator.no_aggregation(vulnerability_list)
        elif level == 1:
            # Level 1, max precision
            aggregation_class_to_vulnerabilities = Aggregator.max_accuracy_aggregation(vulnerability_list)
        elif level == 2:
            # Level 2, same likelihood
            aggregation_class_to_vulnerabilities = Aggregator.same_likelihood_aggregation(vulnerability_list)
        else:
            # Level 3, max compression
            aggregation_class_to_vulnerabilities = Aggregator.max_compression_aggregation(vulnerability_list)
        
        # Return
        return aggregation_class_to_vulnerabilities
