import random
import pymongo



class ScoringEngine():
    
    # RN
    def random_score(local_cve_to_cpe_dnf_tree,local_cpe_to_advisory,local_cpe_to_advisory_max):
        cpe_to_score = dict()

        for cpe in local_cpe_to_advisory:
            cpe_to_score[cpe] = random.random()

        return cpe_to_score
    

    # SR
    def smart_random_score(local_cve_to_cpe_dnf_tree,local_cpe_to_advisory,local_cpe_to_advisory_max):
        cpe_to_score = ScoringEngine.random_score(local_cve_to_cpe_dnf_tree,local_cpe_to_advisory,local_cpe_to_advisory_max)

        return cpe_to_score
    

    # PP
    def heuristic_score(local_cve_to_cpe_dnf_tree,local_cpe_to_advisory,local_cpe_to_advisory_max):
        cpe_to_score = ScoringEngine.recalc_scores(local_cve_to_cpe_dnf_tree,local_cpe_to_advisory,local_cpe_to_advisory_max)

        return cpe_to_score
    

    # VS
    def vulnerability_score_primer(cve_set):
        cve_to_severity = dict()

        dbclient = ScoringEngine.setup_db()

        for cve in cve_set:
            # Probe DB
            mongo_cve = dbclient["VulnDB"]["CVE"].find_one({"_id":cve})
        
            severity = 0
            if mongo_cve != None:
                if "cvss3" in mongo_cve:
                    if "baseScore" in mongo_cve["cvss3"]:
                        severity = mongo_cve["cvss3"]["baseScore"]
                elif "cvss2" in mongo_cve:
                    if "baseScore" in mongo_cve["cvss2"]:
                        severity = mongo_cve["cvss2"]["baseScore"]

            cve_to_severity[cve] = severity

        dbclient.close()


        def vulnerability_score(local_cve_to_cpe_dnf_tree,local_cpe_to_advisory,local_cpe_to_advisory_max):
            cpe_to_score = dict()

            max_cve = set()
            max_cve_severity = -1
            for cve in local_cve_to_cpe_dnf_tree:
                severity = cve_to_severity[cve]
                if severity > max_cve_severity:
                    max_cve_severity = severity
                    max_cve = set()
                    max_cve.add(cve)
                elif severity == max_cve_severity:
                    max_cve.add(cve)

            max_cpe = set()
            all_cpe = set()
            for cve in local_cve_to_cpe_dnf_tree:
                for and_cpe in local_cve_to_cpe_dnf_tree[cve]:
                    for cpe in and_cpe:
                        all_cpe.add(cpe)
                        if cve in max_cve:
                            max_cpe.add(cpe)

            for cpe in all_cpe:
                cpe_to_score[cpe] = 0.1
                if cpe in max_cpe:
                    cpe_to_score[cpe] = 1

            return cpe_to_score
        return vulnerability_score


    # VP
    def vulnerability_heuristic_score_primer(cve_set):
        cve_to_severity = dict()

        dbclient = ScoringEngine.setup_db()

        for cve in cve_set:
            # Probe DB
            mongo_cve = dbclient["VulnDB"]["CVE"].find_one({"_id":cve})
        
            severity = 0
            if mongo_cve != None:
                if "cvss3" in mongo_cve:
                    if "baseScore" in mongo_cve["cvss3"]:
                        severity = mongo_cve["cvss3"]["baseScore"]
                if ("cvss2" in mongo_cve) and (severity == 0):
                    if "baseScore" in mongo_cve["cvss2"]:
                        severity = mongo_cve["cvss2"]["baseScore"]

            cve_to_severity[cve] = severity

        dbclient.close()


        def vulnerability_heuristic_score(local_cve_to_cpe_dnf_tree,local_cpe_to_advisory,local_cpe_to_advisory_max):
            cpe_to_score = dict()

            max_cve = set()
            max_cve_severity = -1
            for cve in local_cve_to_cpe_dnf_tree:
                severity = cve_to_severity[cve]
                if severity > max_cve_severity:
                    max_cve_severity = severity
                    max_cve = set()
                    max_cve.add(cve)
                elif severity == max_cve_severity:
                    max_cve.add(cve)

            cut_cve_to_cpe_dnf_tree = dict()
            for cve in max_cve:
                cut_cve_to_cpe_dnf_tree[cve] = local_cve_to_cpe_dnf_tree[cve]

            cpe_to_score = ScoringEngine.recalc_scores(cut_cve_to_cpe_dnf_tree,local_cpe_to_advisory,local_cpe_to_advisory_max)
            min_score = min(cpe_to_score.values())

            max_cpe = set()
            all_cpe = set()
            for cve in local_cve_to_cpe_dnf_tree:
                for and_cpe in local_cve_to_cpe_dnf_tree[cve]:
                    for cpe in and_cpe:
                        all_cpe.add(cpe)
                        if cve in max_cve:
                            max_cpe.add(cpe)

            for cpe in all_cpe:
                if cpe not in max_cpe:
                    cpe_to_score[cpe] = min_score/2

            return cpe_to_score
        return vulnerability_heuristic_score
    



    ## AUX FUNCTIONS ##

    # Setup db
    def setup_db():
        MongoDBuri = "mongodb://localhost:27017"
        MongoDBclient = pymongo.MongoClient(MongoDBuri)
        return MongoDBclient
    


    # True false score
    def compute_true_false_score(cve_to_cpe_dnf_tree):
        # Null all the scores
        cve_to_cpe_to_true_score_max = dict()
        cve_to_cpe_to_false_score = dict()

        for cve in cve_to_cpe_dnf_tree:
            # Scores are local, for every CPE in each CVE
            cve_to_cpe_to_true_score_max[cve] = dict()
            cve_to_cpe_to_false_score[cve] = dict()

            max_and_degree = 1

            or_degree = len(cve_to_cpe_dnf_tree[cve])

            for and_cpe in cve_to_cpe_dnf_tree[cve]:
                and_degree = len(and_cpe)
                max_and_degree = max(max_and_degree,and_degree)

                for cpe in and_cpe:

                    # Populate structures
                    if cpe not in cve_to_cpe_to_true_score_max[cve]:
                        cve_to_cpe_to_true_score_max[cve][cpe] = 0
                        cve_to_cpe_to_false_score[cve][cpe] = [0,0]

                    # Apply the formulas
                    cve_to_cpe_to_true_score_max[cve][cpe] = max(cve_to_cpe_to_true_score_max[cve][cpe], 1/and_degree)
                    cve_to_cpe_to_false_score[cve][cpe][0] = cve_to_cpe_to_false_score[cve][cpe][0] + 1
                    cve_to_cpe_to_false_score[cve][cpe][1] = cve_to_cpe_to_false_score[cve][cpe][1] + and_degree

            # Normalize
            for cpe in cve_to_cpe_to_true_score_max[cve]:
                cve_to_cpe_to_true_score_max[cve][cpe] = cve_to_cpe_to_true_score_max[cve][cpe] / or_degree
                cve_to_cpe_to_false_score[cve][cpe] = (cve_to_cpe_to_false_score[cve][cpe][1]/max_and_degree) / or_degree
                #cve_to_cpe_to_false_score[cve][cpe] = (cve_to_cpe_to_false_score[cve][cpe][0] + (cve_to_cpe_to_false_score[cve][cpe][1]/max_and_degree)) / or_degree

        # Return
        return cve_to_cpe_to_true_score_max, cve_to_cpe_to_false_score



    # True False score, weighted
    def compute_weighted_true_false_score(cpe_to_advisory,cpe_to_advisory_max,cve_to_cpe_to_true_score_max,cve_to_cpe_to_false_score):
        # Null all the scores
        cve_to_cpe_to_weighted_true_score_max = dict()
        cve_to_cpe_to_weighted_false_score = dict()

        cve_to_cpe_to_combined_score_max = dict()

        for cve in cve_to_cpe_to_true_score_max:
            # Scores are local, for every CPE in each CVE
            cve_to_cpe_to_weighted_true_score_max[cve] = dict()
            cve_to_cpe_to_weighted_false_score[cve] = dict()

            cve_to_cpe_to_combined_score_max[cve] = dict()

            for cpe in cve_to_cpe_to_true_score_max[cve]:
                # Apply the formulas
                cve_to_cpe_to_weighted_true_score_max[cve][cpe] = ((len(cpe_to_advisory[cpe])/cpe_to_advisory_max)*cve_to_cpe_to_true_score_max[cve][cpe])
                cve_to_cpe_to_weighted_false_score[cve][cpe] = ((1-(len(cpe_to_advisory[cpe])/cpe_to_advisory_max))*cve_to_cpe_to_false_score[cve][cpe])

                # S = a*T + b*F
                cve_to_cpe_to_combined_score_max[cve][cpe] = cve_to_cpe_to_weighted_true_score_max[cve][cpe] + cve_to_cpe_to_weighted_false_score[cve][cpe]

        # Return
        return cve_to_cpe_to_weighted_true_score_max,cve_to_cpe_to_weighted_false_score,cve_to_cpe_to_combined_score_max



    # Mean Sum score
    def compute_mean_sum_score(cve_to_cpe_to_combined_score_max):
        # Initialize variables
        cpe_to_mean_score = dict()
        cpe_to_sum_score = dict()
        cpe_to_cross_cve_score = dict()

        # Counter
        cpe_counter = dict()

        for cve in cve_to_cpe_to_combined_score_max:
            for cpe in cve_to_cpe_to_combined_score_max[cve]:
                # Populate the dictionaries
                if cpe not in cpe_to_sum_score:
                    cpe_to_sum_score[cpe] = 0
                if cpe not in cpe_counter:
                    cpe_counter[cpe] = 0
                
                # Calculate the sum score
                cpe_to_sum_score[cpe] = cpe_to_sum_score[cpe] + cve_to_cpe_to_combined_score_max[cve][cpe]

                # Add to the counter
                cpe_counter[cpe] = cpe_counter[cpe] + 1

        # Mean score
        for cpe in cpe_to_sum_score:
            cpe_to_mean_score[cpe] = cpe_to_sum_score[cpe] / cpe_counter[cpe]

        # Final score
        for cpe in cpe_to_sum_score:
            cpe_to_cross_cve_score[cpe] = (cpe_to_sum_score[cpe]/len(cve_to_cpe_to_combined_score_max)) * cpe_to_mean_score[cpe]
            # RISK = LIKELIHOOD * IMPACT
            # LIKELIHOOD = SUM OF CPE IMPACTS [0-1] NORMALIZED ACROSS THE WHOLE CVE SET
            # IMPACT = CPE MEAN SCORE, WHEN CPE IS PRESENT

        # Return
        return cpe_to_mean_score, cpe_to_sum_score, cpe_to_cross_cve_score



    # Calculate the scores
    def recalc_scores(local_cve_to_cpe_dnf_tree,local_cpe_to_advisory,local_cpe_to_advisory_max):
        cve_to_cpe_to_true_score_max,cve_to_cpe_to_false_score = ScoringEngine.compute_true_false_score(local_cve_to_cpe_dnf_tree)
        _,_,cve_to_cpe_to_combined_score_max = ScoringEngine.compute_weighted_true_false_score(local_cpe_to_advisory,local_cpe_to_advisory_max,cve_to_cpe_to_true_score_max,cve_to_cpe_to_false_score)
        _,cpe_to_sum_score,_ = ScoringEngine.compute_mean_sum_score(cve_to_cpe_to_combined_score_max)
        return cpe_to_sum_score



