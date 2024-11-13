import os
import re
import json
import math
import pymongo

from threading import Thread

import sympy

import xml.etree.ElementTree as ET

from neo4j import GraphDatabase



VERSION = True



#"""
print("Retrieving Inventory data")

host_to_nvt_to_cve = dict()
host_to_plugin_to_cve = dict()

# Scan the folder for nessus and openvas files
RESOURCES_DIR = "resources"
CYBERRANGE_DATA_DIR = "dataset"
CYBERRANGE_INPUT_DIR = CYBERRANGE_DATA_DIR+"/network_scan"
CYBERRANGE_OUTPUT_DIR = CYBERRANGE_DATA_DIR+"/raw_inventories"

for filename in os.listdir(CYBERRANGE_INPUT_DIR):
    # OPENVAS
    if "report-" in filename:
        f = os.path.join(CYBERRANGE_INPUT_DIR, filename)
        if os.path.isfile(f):

            # Grab openvas data from metafiles
            openvasscan = ET.parse(f)

            # Unwind openvas
            root = openvasscan.getroot()

            report = None
            for child in root:
                if child.tag == "report":
                    report = child
                    break

            results = None
            for child in report:
                if child.tag == "results":
                    results = child
                    break

            result_list = list()
            for child in results:
                result_list.append(child)

            host_to_nvt = dict()
            nvt_to_cve = dict()
            for result in result_list:

                host_id = ""
                nvt_id = ""

                for child in result:

                    if child.tag == "host":
                        host_id = child.text.strip()
                        if host_id not in host_to_nvt:
                            host_to_nvt[host_id] = set()

                    if child.tag == "nvt":
                        nvt_id = child.attrib["oid"]
                        if nvt_id not in nvt_to_cve:
                            nvt_to_cve[nvt_id] = set()

                        for nvtchild in child:
                            if nvtchild.tag == "refs":
                                for ref in nvtchild:
                                    if ref.attrib["type"] == "cve":
                                        nvt_to_cve[nvt_id].add(ref.attrib["id"])
                    
                if (host_id != "") and (nvt_id != ""):
                    host_to_nvt[host_id].add(nvt_id)

            old_host_to_nvt = host_to_nvt
            host_to_nvt = dict()
            for elem in old_host_to_nvt:
                if old_host_to_nvt[elem] != set():
                    host_to_nvt[elem] = list(old_host_to_nvt[elem])
            old_host_to_nvt = None

            old_nvt_to_cve = nvt_to_cve
            nvt_to_cve = dict()
            for elem in old_nvt_to_cve:
                if old_nvt_to_cve[elem] != set():
                    nvt_to_cve[elem] = list(old_nvt_to_cve[elem])
            old_nvt_to_cve = None

            for host in host_to_nvt:
                host_to_nvt_to_cve[host] = dict()
                for nvt in host_to_nvt[host]:
                    if nvt in nvt_to_cve:
                        host_to_nvt_to_cve[host][nvt] = nvt_to_cve[nvt]


    # NESSUS
    elif ".nessus" in filename:
        f = os.path.join(CYBERRANGE_INPUT_DIR, filename)
        if os.path.isfile(f):

            # Grab nessus data from metafiles
            nessusscan = ET.parse(f)

            # Unwind nessus
            root = nessusscan.getroot()
            report = None
            for child in root:
                if child.tag == "Report":
                    report = child
                    break

            host_list = list()
            for child in report:
                if child.tag == "ReportHost":
                    host_list.append(child)

            for host in host_list:
                host_id = host.attrib["name"]
                if host_id not in host_to_plugin_to_cve:
                    host_to_plugin_to_cve[host_id] = dict()

                for report in host:
                    if report.tag == "ReportItem":
                        plugin_id = report.attrib["pluginID"]
                        if plugin_id not in host_to_plugin_to_cve[host_id]:
                            host_to_plugin_to_cve[host_id][plugin_id] = set()

                        for item in report:
                            if item.tag == "cve":
                                host_to_plugin_to_cve[host_id][plugin_id].add(item.text.strip())



"""
# neo4j DB
DBuri = "bolt://localhost:7687"
#DBuri = "bolt://151.100.59.83:11763"
#DBuri = "bolt://awareserver.diag.uniroma1.it:11759"

# DB connection
DBdriver = GraphDatabase.driver(DBuri, auth=("neo4j", "password"), encrypted=False)
#DBdriver = GraphDatabase.driver(DBuri, auth=("vamp", "vamp"), encrypted=False)



def grab_glsa_to_cve(tx):
    result = dict()
    query = tx.run("MATCH (a:GLSA)-->(b:CVE) "+
                   "RETURN distinct a.id AS advisory, b.id AS cve")
    for record in query:
        if record["advisory"] not in result:
            result[record["advisory"]] = list()
        result[record["advisory"]].append(record["cve"])
    return result

def grab_nessus_to_cve(tx):
    result = dict()
    query = tx.run("MATCH (a:NessusPlugin)-->(b:CVE) "+
                   "RETURN distinct a.id AS advisory, b.id AS cve")
    for record in query:
        if record["advisory"] not in result:
            result[record["advisory"]] = list()
        result[record["advisory"]].append(record["cve"])
    return result
#"""


print("Retrieving DB data")

# Disclaimer
print("!!Disclaimer!!")
print("It is assumed that a mongodb database with CVE, NessusPlugins and GLSAs is present and running on this machine")
print("If this is not the case, place your own NVD dump in resources/ and swap the blocks of code below")
print("We could not bundle our own NVD dump as it weights 1GB")

# Retrieving data from MongoDB
MongoDBuri = "mongodb://localhost:27017"
MongoDBclient = pymongo.MongoClient(MongoDBuri)

CVEMongoTable = MongoDBclient["VulnDB"]["CVE"].find()
GLSAMongoTable = MongoDBclient["VulnDB"]["GLSA"].find()
NessusMongoTable = MongoDBclient["VulnDB"]["NessusPlugin"].find()


# Alternate DB files
"""
f=open(file=RESOURCES_DIR+"/nvd_checkpoint.json",mode="r",encoding="utf-8")
CVEMongoTable = json.loads(f.read())
f.close()

f=open(file=RESOURCES_DIR+"/VulnDB.GLSA.json",mode="r",encoding="utf-8")
GLSAMongoTable = json.loads(f.read())
f.close()

f=open(file=RESOURCES_DIR+"/VulnDB.NessusPlugin_chunk1.json",mode="r",encoding="utf-8")
NessusMongoTable = json.loads(f.read())
f.close()

f=open(file=RESOURCES_DIR+"/VulnDB.NessusPlugin_chunk2.json",mode="r",encoding="utf-8")
NessusMongoTable.update(json.loads(f.read()))
f.close()

f=open(file=RESOURCES_DIR+"/VulnDB.NessusPlugin_chunk3.json",mode="r",encoding="utf-8")
NessusMongoTable.update(json.loads(f.read()))
f.close()
#"""


mongo_cve_dict = dict()
for cve in CVEMongoTable:
    mongo_cve_dict[cve["id"]] = cve

mongo_glsa_dict = dict()
for advisory in GLSAMongoTable:
    mongo_glsa_dict[advisory["id"]] = advisory

mongo_nessus_dict = dict()
for advisory in NessusMongoTable:
    mongo_nessus_dict[advisory["id"]] = advisory

# End database stuff



# Target set
print("Compiling target sets")
device_to_target_cve_set = dict()

target_cve_set = set()
target_nessus_advisory_set = set()
target_openvas_advisory_set = set()

cve_not_in_mongo_count = 0


for device in host_to_nvt_to_cve:
    if device not in device_to_target_cve_set:
        device_to_target_cve_set[device] = set()
    for advisory in host_to_nvt_to_cve[device]:
        target_openvas_advisory_set.add(advisory)
        for cve_id in host_to_nvt_to_cve[device][advisory]:
            if cve_id in mongo_cve_dict:
                device_to_target_cve_set[device].add(cve_id)
                target_cve_set.add(cve_id)
            else:
                cve_not_in_mongo_count += 1

for device in host_to_plugin_to_cve:
    if device not in device_to_target_cve_set:
        device_to_target_cve_set[device] = set()
    for advisory in host_to_plugin_to_cve[device]:
        target_nessus_advisory_set.add(advisory)
        for cve_id in host_to_plugin_to_cve[device][advisory]:
            if cve_id in mongo_cve_dict:
                device_to_target_cve_set[device].add(cve_id)
                target_cve_set.add(cve_id)
            else:
                cve_not_in_mongo_count += 1


print("#ADV NESSUS ",len(target_nessus_advisory_set))
print("#ADV OPENVAS ",len(target_openvas_advisory_set))
print("#CVE ",len(target_cve_set))
if cve_not_in_mongo_count > 0:
    print("WARN #CVE NOT IN MONGO ",cve_not_in_mongo_count)
#input("continue?")



print("Compiling cpe indexes")
def strip_cpe(cpe):
    cpe = cpe[cpe.find(":")+1:]
    cpe = cpe[cpe.find(":")+1:]
    part = cpe[:cpe.find(":")]
    cpe = cpe[cpe.find(":")+1:]
    vendor = cpe[:cpe.find(":")]
    cpe = cpe[cpe.find(":")+1:]
    product = cpe[:cpe.find(":")]
    cpe = cpe[cpe.find(":")+1:]
    version = cpe[:cpe.find(":")]
    
    newcpe = part+":"+vendor+":"+product+":"+version

    # CPE sanitization
    if "&" in newcpe:
        newcpe = newcpe.replace("&","")
    if "\\" in newcpe:
        newcpe = newcpe.replace("\\","")
    if "/" in newcpe:
        newcpe = newcpe.replace("/","")
        
    return newcpe


# CPE Dictionaries
cve_to_cpe_part_vendor_product_version = dict()
cve_to_cpe_part_vendor_product = dict()
cve_to_cpe_vendor_product = dict()
cve_to_cpe_vendor = dict()
cve_to_cpe = dict()

device_to_vendor_to_product_to_version = dict()

for device in device_to_target_cve_set:
    for cve_id in device_to_target_cve_set[device]:
        if cve_id in mongo_cve_dict:
            cve = mongo_cve_dict[cve_id]
            cve_to_cpe[cve_id] = list(set(cve["cpe_strings"]))

            part_vendor_product_version_set = set()
            part_vendor_product_set = set()
            vendor_product_set = set()
            vendor_set = set()

            for cpe in cve_to_cpe[cve_id]:
                cpe = strip_cpe(cpe)

                part = cpe[:cpe.find(":")]
                cpe = cpe[cpe.find(":")+1:]
                vendor = cpe[:cpe.find(":")]
                cpe = cpe[cpe.find(":")+1:]
                product = cpe[:cpe.find(":")]
                cpe = cpe[cpe.find(":")+1:]
                version = cpe

                part_vendor_product_version_set.add(part+":"+vendor+":"+product+":"+version)
                part_vendor_product_set.add(part+":"+vendor+":"+product)
                vendor_product_set.add(vendor+":"+product)
                vendor_set.add(vendor)

                if device not in device_to_vendor_to_product_to_version:
                    device_to_vendor_to_product_to_version[device] = dict()
                if vendor not in device_to_vendor_to_product_to_version[device]:
                    device_to_vendor_to_product_to_version[device][vendor] = dict()
                if product not in device_to_vendor_to_product_to_version[device][vendor]:
                    device_to_vendor_to_product_to_version[device][vendor][product] = set()
                device_to_vendor_to_product_to_version[device][vendor][product].add(version)

            if cve_id not in cve_to_cpe_part_vendor_product_version:
                cve_to_cpe_part_vendor_product_version[cve_id] = set()
                cve_to_cpe_part_vendor_product[cve_id] = set()
                cve_to_cpe_vendor_product[cve_id] = set()
                cve_to_cpe_vendor[cve_id] = set()
            cve_to_cpe_part_vendor_product_version[cve_id] = cve_to_cpe_part_vendor_product_version[cve_id].union(part_vendor_product_version_set)
            cve_to_cpe_part_vendor_product[cve_id] = cve_to_cpe_part_vendor_product[cve_id].union(part_vendor_product_set)
            cve_to_cpe_vendor_product[cve_id] = cve_to_cpe_vendor_product[cve_id].union(vendor_product_set)
            cve_to_cpe_vendor[cve_id] = cve_to_cpe_vendor[cve_id].union(vendor_set)



print("Compiling cpe dnf")
cpe_set = set()
for cve_id in mongo_cve_dict:
    cve = mongo_cve_dict[cve_id]
    for cpe in cve["cpe_strings"]:
        cpe_set.add(strip_cpe(cpe))

cpe_to_symbol = dict()
symbol_to_cpe = dict()
cpenum = 0
for cpe in cpe_set:
    symbol = sympy.symbols(str(cpenum))
    cpe_to_symbol[cpe] = symbol
    symbol_to_cpe[symbol] = cpe
    cpenum = cpenum + 1



# Boolean CNF encoding
def encode_to_boolean(cpe_config,debug=False):
    local_children_count = len(cpe_config["children"])
    local_cpe_count = len(cpe_config["cpe"])

    result = None

    if local_children_count > 0:
        is_first_child = True
        for child in cpe_config["children"]:
            if is_first_child:
                result = (encode_to_boolean(child,debug))
                is_first_child = False
            else:
                if cpe_config["operator"] == "OR":
                    result = sympy.Or(result, (encode_to_boolean(child,debug)))
                else:
                    result = sympy.And(result, (encode_to_boolean(child,debug)))

    if local_cpe_count > 0:
        is_first_cpe = True
        for cpe in cpe_config["cpe"]:
            if is_first_cpe:
                result = cpe_to_symbol[strip_cpe(cpe["cpe"])]
                is_first_cpe = False
            else:
                if cpe_config["operator"] == "OR":
                    result = sympy.Or(result, cpe_to_symbol[strip_cpe(cpe["cpe"])])
                else:
                    result = sympy.And(result, cpe_to_symbol[strip_cpe(cpe["cpe"])])
    
    return result


def encode_to_boolean_first_step(cpe_config_list,debug=False):
    if debug:
        print("- ",cpe_config_list)

    is_first_config = True
    result = None
    
    for config in cpe_config_list:
        if debug:
            print("> ",config,"//",len(config["cpe"]),"//",len(config["children"]))
        if (len(config["cpe"]) > 0) or (len(config["children"]) > 0):
            if is_first_config:
                if debug:
                    print("# first # ",result)
                result = (encode_to_boolean(config,debug))
                is_first_config = False
            else:
                if debug:
                    print("# not first # ",result)
                result = sympy.Or(result, (encode_to_boolean(config,debug)))
    return result


cve_to_cnf = dict()
cve_to_dnf = dict()
cve_to_cnf_symbol = dict()
cve_to_dnf_symbol = dict()

threadpool = list()


def thread_worker(cve_id):
    print(cve_id," START")
    cve = mongo_cve_dict[cve_id]

    """
    # Debug!
    encoded_configurations = None
    if cve_id == "CVE-2018-0315":
        encoded_configurations = encode_to_boolean_first_step(cve["cpe_configurations"],True)
        input("breakpoint!")
    else:
        encoded_configurations = encode_to_boolean_first_step(cve["cpe_configurations"],False)
    #"""

    encoded_configurations = encode_to_boolean_first_step(cve["cpe_configurations"],False)

    if encoded_configurations != None:
        encoded_configurations = sympy.logic.simplify_logic(encoded_configurations)
    #cnf_cpe = sympy.to_cnf(encoded_configurations)
    dnf_cpe = sympy.to_dnf(encoded_configurations)
    
    # Side effect
    if dnf_cpe != None:
        #cve_to_cnf_symbol[cve_id] = cnf_cpe
        cve_to_dnf_symbol[cve_id] = dnf_cpe

    print(cve_id," END")
    #return cve_id,dnf_cpe


#"""
# Multithread
print("Starting threads")
for cve_id in target_cve_set:
    threadpool.append(Thread(target=thread_worker,args=(cve_id,)))

for thread in threadpool:
    thread.start()

for thread in threadpool:
    thread.join()
#"""

"""
# Singleprocess
for cve_id in target_cve_set:
    thread_worker(cve_id)

    #if cve_id in cve_to_dnf_symbol:
        #cnf = cve_to_cnf_symbol[cve_id]
        #dnf = cve_to_dnf_symbol[cve_id]
        #print("CN-",cve_to_cnf[cve_id])
        #print("CS-",sympy.logic.simplify_logic(cnf))
        #print("DN-",dnf)
        #print("DS-",sympy.logic.simplify_logic(dnf))
#"""



#"""
# Decode symbolic cpe
for cve_id in cve_to_dnf_symbol:
    #"""

    """
    formula = cve_to_cnf_symbol[cve_id]
    formula = " "+str(formula)+" "
    formula = formula.replace("(","( ")
    formula = formula.replace(")"," )")

    work_formula = formula.replace("(","")
    work_formula = work_formula.replace(")","")
    work_formula = work_formula.replace("|","")
    work_formula = work_formula.replace("&","")
    
    work_splitformula = work_formula.strip().split(" ")

    for work_split in work_splitformula:
        if work_split != "":
            work_split = work_split.strip()
            if sympy.symbols(work_split) in symbol_to_cpe:
                formula = formula.replace(" "+work_split+" "," "+symbol_to_cpe[sympy.symbols(work_split)]+" ",1)

    cve_to_cnf[cve_id] = formula
    #"""

#"""
    formula = cve_to_dnf_symbol[cve_id]
    formula = " "+str(formula)+" "
    formula = formula.replace("(","( ")
    formula = formula.replace(")"," )")
    
    work_formula = formula.replace("(","")
    work_formula = work_formula.replace(")","")
    work_formula = work_formula.replace("|","")
    work_formula = work_formula.replace("&","")

    work_splitformula = work_formula.strip().split(" ")

    for work_split in work_splitformula:
        if work_split != "":
            work_split = work_split.strip()

            if sympy.symbols(work_split) in symbol_to_cpe:
                formula = formula.replace(" "+work_split+" "," "+symbol_to_cpe[sympy.symbols(work_split)]+" ",1)
    
    cve_to_dnf[cve_id] = formula.strip()
#"""



#"""
# Structure CPE tree
target_cpe_set = set()
cve_to_dnf_tree = dict()

for cve in cve_to_dnf:
    cve_to_dnf_tree[cve] = list()

    work_formula = cve_to_dnf[cve]

    or_split = work_formula.split("|")
    for elem in or_split:
        and_set = set()

        and_split = elem.replace("(","").replace(")","").strip().split("&")
        for elem2 in and_split:
            elem2 = elem2.strip()
            and_set.add(elem2)
            target_cpe_set.add(elem2)

        cve_to_dnf_tree[cve].append(list(and_set))
#"""



# Compare versions
def version_compare(current,condition):
    #print("START")
    #print(current," : ",condition)

    # Define operator
    operator = "="
    if condition.startswith(">="):
        operator = ">="
        condition = condition.replace(">= ","")
    elif condition.startswith("<="):
        operator = "<="
        condition = condition.replace("<= ","")
    elif condition.startswith(">"):
        operator = ">"
        condition = condition.replace("> ","")
    elif condition.startswith("<"):
        operator = "<"
        condition = condition.replace("< ","")

    #print(current," : ",condition)

    # Version to number
    current_number = version_to_number(current)
    condition_number = version_to_number(condition)

    #print(current," : ",condition)

    # Perform operation function
    def perform_operation(elem1,elem2,operator):

        if operator == "=":
            return elem1 == elem2
        elif operator == ">=":
            return elem1 >= elem2
        elif operator == "<=":
            return elem1 <= elem2
        elif operator == ">":
            return elem1 > elem2
        elif operator == "<":
            return elem1 < elem2
        # Return check, strictcheck
        # Example <=, <
        # If second return is true, don't go further
        return False
    
    # Perform op
    return perform_operation(current_number,condition_number,operator)



# Version to numerical encoding
def strip_version(version):
    return re.sub(r"[^0-9.]","",version).strip()



# Version to numerical encoding
def version_to_number(version):
    retnum = 0

    # I assume to have versions, subversions and such up to 100
    # I also assume atmost a depth 4 subversion
    maxvers = 100
    maxdepth = 4

    # Ignore non numeric stuff
    version = strip_version(version)
    #print(version)

    # Split the dots
    splitversion = version.split(".")
    for index in range(len(splitversion)):
        #print(index)
        if (index < maxdepth) and splitversion[index].strip().isnumeric():
            elem = int(splitversion[index].strip())
            retnum = retnum + (elem*math.pow(maxvers,(maxdepth-index-1)))
            #print(elem,(elem*math.pow(maxvers,(maxdepth-index-1))))

    #print(retnum)

    return int(retnum)



# FORMAT OUTPUT
def format_output(current_host_to_advisory_to_cve, current_cve_to_dnf_tree, current_cve_to_cpe_part_vendor_product_version, USE_VERSION):

    def ignore_version_on_dnf_tree(node):
        if (USE_VERSION == True):
            return node
        
        work_node = set()
        for and_cpe in node:
            new_and_cpe = set()
            for cpe in and_cpe:
                new_cpe = cpe[:cpe.rfind(":")]
                new_and_cpe.add(new_cpe)
            work_node.add(frozenset(new_and_cpe))

        new_node = list()
        for elem in work_node:
            new_node.append(list(elem))

        return list(new_node)


    out_device_to_target_cve_set = dict()
    out_device_to_advisory_to_cve = dict()
    for device in current_host_to_advisory_to_cve:
        out_device_to_target_cve_set[device] = set()
        out_device_to_advisory_to_cve[device] = dict()
        for advisory in current_host_to_advisory_to_cve[device]:

            if advisory not in out_device_to_advisory_to_cve[device]:
                out_device_to_advisory_to_cve[device][advisory] = set()

            for cve in current_host_to_advisory_to_cve[device][advisory]:
                if cve in target_cve_set:
                    out_device_to_target_cve_set[device].add(cve)
                    out_device_to_advisory_to_cve[device][advisory].add(cve)


    for device in out_device_to_advisory_to_cve:
        for advisory in out_device_to_advisory_to_cve[device]:
            out_device_to_advisory_to_cve[device][advisory] = list(out_device_to_advisory_to_cve[device][advisory])


    out_device_to_cve_to_cpe = dict()
    for device in out_device_to_target_cve_set:
        out_device_to_cve_to_cpe[device] = dict()
        for cve in out_device_to_target_cve_set[device]:
            if cve in current_cve_to_dnf_tree:
                out_device_to_cve_to_cpe[device][cve] = ignore_version_on_dnf_tree(current_cve_to_dnf_tree[cve])


    out_device_to_cpe_to_advisory = dict()
    for device in current_host_to_advisory_to_cve:
        if device not in out_device_to_cpe_to_advisory:
            out_device_to_cpe_to_advisory[device] = dict()
        for advisory in current_host_to_advisory_to_cve[device]:
            for cve in current_host_to_advisory_to_cve[device][advisory]:
                if cve in current_cve_to_dnf_tree:
                    for and_cpe in ignore_version_on_dnf_tree(current_cve_to_dnf_tree[cve]):
                        for cpe in and_cpe:
                            if cpe not in out_device_to_cpe_to_advisory[device]:
                                out_device_to_cpe_to_advisory[device][cpe] = set()
                            out_device_to_cpe_to_advisory[device][cpe].add(advisory)


    for device in out_device_to_advisory_to_cve:
        for cpe in out_device_to_cpe_to_advisory[device]:
            out_device_to_cpe_to_advisory[device][cpe] = list(out_device_to_cpe_to_advisory[device][cpe])


    out_device_to_cpe_inventory = dict()
    for device in out_device_to_target_cve_set:
        out_device_to_cpe_inventory[device] = dict()
        for cve in out_device_to_target_cve_set[device]:
            if cve in current_cve_to_cpe_part_vendor_product_version:
                for cpe in current_cve_to_cpe_part_vendor_product_version[cve]:
                    out_device_to_cpe_inventory[device][cpe] = "unknown"

    return out_device_to_target_cve_set,out_device_to_advisory_to_cve,out_device_to_cve_to_cpe,out_device_to_cpe_to_advisory,out_device_to_cpe_inventory



host_to_pluginornvt_to_cve = dict()
for host in host_to_plugin_to_cve:
    if host not in host_to_pluginornvt_to_cve:
        host_to_pluginornvt_to_cve[host] = dict()
    for advisory in host_to_plugin_to_cve[host]:
        if advisory not in host_to_pluginornvt_to_cve[host]:
            host_to_pluginornvt_to_cve[host][advisory] = set()
        for cve in host_to_plugin_to_cve[host][advisory]:
            host_to_pluginornvt_to_cve[host][advisory].add(cve)

for host in host_to_nvt_to_cve:
    if host not in host_to_pluginornvt_to_cve:
        host_to_pluginornvt_to_cve[host] = dict()
    for advisory in host_to_nvt_to_cve[host]:
        if advisory not in host_to_pluginornvt_to_cve[host]:
            host_to_pluginornvt_to_cve[host][advisory] = set()
        for cve in host_to_nvt_to_cve[host][advisory]:
            host_to_pluginornvt_to_cve[host][advisory].add(cve)


# Version output
out_device_to_target_cve_set_version_merged,out_device_to_advisory_to_cve_version_merged,out_device_to_cve_to_cpe_version_merged,out_device_to_cpe_to_advisory_version_merged,out_device_to_cpe_inventory_version_merged = dict(),dict(),dict(),dict(),dict()
out_device_to_target_cve_set_version_nessus,out_device_to_advisory_to_cve_version_nessus,out_device_to_cve_to_cpe_version_nessus,out_device_to_cpe_to_advisory_version_nessus,out_device_to_cpe_inventory_version_nessus = dict(),dict(),dict(),dict(),dict()
out_device_to_target_cve_set_version_openvas,out_device_to_advisory_to_cve_version_openvas,out_device_to_cve_to_cpe_version_openvas,out_device_to_cpe_to_advisory_version_openvas,out_device_to_cpe_inventory_version_openvas = dict(),dict(),dict(),dict(),dict()
if VERSION == True:
    print("Version output")
    out_device_to_target_cve_set_version_merged,out_device_to_advisory_to_cve_version_merged,out_device_to_cve_to_cpe_version_merged,out_device_to_cpe_to_advisory_version_merged,out_device_to_cpe_inventory_version_merged = format_output(host_to_pluginornvt_to_cve,cve_to_dnf_tree,cve_to_cpe_part_vendor_product_version,True)
    out_device_to_target_cve_set_version_nessus,out_device_to_advisory_to_cve_version_nessus,out_device_to_cve_to_cpe_version_nessus,out_device_to_cpe_to_advisory_version_nessus,out_device_to_cpe_inventory_version_nessus = format_output(host_to_plugin_to_cve,cve_to_dnf_tree,cve_to_cpe_part_vendor_product_version,True)
    out_device_to_target_cve_set_version_openvas,out_device_to_advisory_to_cve_version_openvas,out_device_to_cve_to_cpe_version_openvas,out_device_to_cpe_to_advisory_version_openvas,out_device_to_cpe_inventory_version_openvas = format_output(host_to_nvt_to_cve,cve_to_dnf_tree,cve_to_cpe_part_vendor_product_version,True)

device_set = set(out_device_to_target_cve_set_version_merged.keys())


#"""
print("Output snapshot meta")
os.mkdir(CYBERRANGE_OUTPUT_DIR+"/cyberrange_merged")

f = open(file=CYBERRANGE_OUTPUT_DIR+"/cyberrange_merged/snapshot_meta.json",mode="w",encoding="utf-8")
f.write(json.dumps({"hosts":list(device_set)}))
f.close()


# Merged
print("Merged")
for device in device_set:
    print("Output device "+device)
    os.mkdir(CYBERRANGE_OUTPUT_DIR+"/cyberrange_merged/"+device)

    if VERSION == True:
        f = open(file=CYBERRANGE_OUTPUT_DIR+"/cyberrange_merged/"+device+"/advisory_to_cve.json",mode="w",encoding="utf-8")
        f.write(json.dumps(out_device_to_advisory_to_cve_version_merged[device]))
        f.close()

        f = open(file=CYBERRANGE_OUTPUT_DIR+"/cyberrange_merged/"+device+"/cve_to_cpe.json",mode="w",encoding="utf-8")
        f.write(json.dumps(out_device_to_cve_to_cpe_version_merged[device]))
        f.close()

        f = open(file=CYBERRANGE_OUTPUT_DIR+"/cyberrange_merged/"+device+"/cpe_to_advisory.json",mode="w",encoding="utf-8")
        f.write(json.dumps(out_device_to_cpe_to_advisory_version_merged[device]))
        f.close()

        f = open(file=CYBERRANGE_OUTPUT_DIR+"/cyberrange_merged/"+device+"/validation_inventory.json",mode="w",encoding="utf-8")
        f.write(json.dumps(out_device_to_cpe_inventory_version_merged[device]))
        f.close()
#"""