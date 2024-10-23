import random, hashlib, statistics

def get_derivative_features(vuln):
    if "cvssMetricV2" in vuln["metrics"]:
        metricV2 = vuln["metrics"]["cvssMetricV2"][0]
        impact = metricV2["impactScore"]
        likelihood = metricV2["exploitabilityScore"]
        score = metricV2["cvssData"]["baseScore"]
    elif "cvssMetricV30" in vuln["metrics"]:
        metricV3 = vuln["metrics"]["cvssMetricV30"][0]
        impact = metricV3["impactScore"]
        likelihood = metricV3["exploitabilityScore"]
        score = metricV3["cvssData"]["baseScore"]
    elif "cvssMetricV31" in vuln["metrics"]:
        metricV3 = vuln["metrics"]["cvssMetricV31"][0]
        impact = metricV3["impactScore"]
        likelihood = metricV3["exploitabilityScore"]
        score = metricV3["cvssData"]["baseScore"]
    else: #default values
        impact = 5 
        likelihood = 5
        score = 5
    return impact,likelihood,score

def reachability_to_attack(reachability_path,devices,vulnerabilities,steering_vulns):
    processed_targets={}
    trace = ""
    impacts=[]
    likelihoods=[]
    scores=[]
    vulnerabilities_path = []
    for edge in reachability_path:
        target_hostname = edge[1]
        if target_hostname not in processed_targets.keys():
            vulns_edge = get_vulns_by_hostname(target_hostname,devices)
            processed_targets[target_hostname] = vulns_edge
        else:
            vulns_edge = processed_targets[target_hostname]
        if len(vulns_edge)<=0: continue
        
        steering_compliant_vulns = []
        for v_edge in vulns_edge:
            if v_edge in steering_vulns: steering_compliant_vulns.append(v_edge)

        if len(steering_compliant_vulns)>0:
            attack_vuln = random.choice(steering_compliant_vulns)
        else:
            attack_vuln = random.choice(vulns_edge)
        vuln,pre,post = retrieve_privileges(attack_vuln,vulnerabilities)
        src=pre+"@"+str(edge[0])
        dst=post+"@"+str(target_hostname)

        if edge == reachability_path[-1]: trace += src+"#"+attack_vuln+"#"+dst
        else: trace += src+"#"+attack_vuln+"#"+dst+"##"

        vulnerabilities_path.append(vuln)
        impact,likelihood,score=get_derivative_features(vuln)
        impacts.append(impact)
        likelihoods.append(likelihood)
        scores.append(score)

    return {
        "id": hashlib.sha256(str(trace).encode("utf-8")).hexdigest(),
        "trace": trace,
        "length": len(impacts),
        "impact": statistics.median(impacts), #sum(impacts)/len(impacts),
        "likelihood": statistics.median(likelihoods), #sum(likelihoods)/len(likelihoods),
        "score" : statistics.median(scores), #sum(scores)/len(scores)
    }, vulnerabilities_path

