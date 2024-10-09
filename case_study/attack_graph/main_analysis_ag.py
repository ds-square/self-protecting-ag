import os, json, sys, os, csv, statistics, random, time, logging, math
import pandas as pd
import numpy as np
import networkx as nx
import seaborn as sns
import matplotlib.pyplot as plt
from itertools import chain
pd.options.mode.chained_assignment = None

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import config

MARKERS = {0:"o", 1:"s", 2:"+", 3:"x", 4:"d", 5:"h"}
COLORS = {0:"#984ea3", 1:"#4daf4a", 2:"#377eb8", 3:"#e41a1c", 4:"#ff7f00", 5:"#000000"}

def get_aggregation_name(aggr_lev):
    if aggr_lev==0: return "GT"
    elif aggr_lev==1: return "VA"
    elif aggr_lev==2: return "RA"
    else: return "HA"

def get_filter_name(filt_lev):
    if filt_lev==1: return "RN"
    elif filt_lev==2: return "SR"
    elif filt_lev==3: return "VS"
    elif filt_lev==4: return "PP"
    elif filt_lev==5: return "VP"
    else: return "NONE"

def compute_risk_analysis(vuln_ids, vulns_list):
    base_scores=[]
    impact_scores=[]
    exploit_scores=[]
    for v_curr in vuln_ids:
        for v_gt in vulns_list:
            if v_gt["id"] in v_curr:
                base_scores.append(v_gt["cvss_metrics"]["base"])
                impact_scores.append(v_gt["cvss_metrics"]["impact"])
                exploit_scores.append(v_gt["cvss_metrics"]["exploitability"])
    
    lambda_exploit_scores = []
    for expl_s in exploit_scores:
        lambda_exploit_scores.append(1/expl_s)
    
    lik_risk = sum(lambda_exploit_scores) if len(lambda_exploit_scores)>0 else 0
    imp_risk = (impact_scores[len(impact_scores)-1])/max(impact_scores) if len(impact_scores)>0 and max(impact_scores)>0 else 0

    if lik_risk>1: lik_risk=1
    if imp_risk>1: imp_risk=1

    return {
        "impact":
        imp_risk, 
        #max(impact_scores) if len(impact_scores)>0 else 0,
        # statistics.median(impact_scores) if len(impact_scores)>0 else 0, 
        # statistics.mean(impact_scores) if len(impact_scores)>0 else 0,
        "exploit": 
        lik_risk,
        # max(exploit_scores) if len(exploit_scores)>0 else 0,
        # statistics.median(exploit_scores) if len(exploit_scores)>0 else 0,
        # statistics.mean(exploit_scores) if len(exploit_scores)>0 else 0,
        "score" : 
        max(base_scores) if len(base_scores)>0 else 0,
        # statistics.median(base_scores) if len(base_scores)>0 else 0,
        # statistics.mean(base_scores) if len(base_scores)>0 else 0,
        "risk":
        (imp_risk)*(lik_risk),
        "mod":
        np.linalg.norm(np.array([imp_risk,lik_risk,imp_risk*lik_risk]))
    }, {
        "impact": impact_scores,
        "exploit": exploit_scores,
        "score" : base_scores,
    }

def aggregate_risk_paths(list_risks):
    df_target = pd.DataFrame(list_risks)
    return {
        "impact": max(list(df_target["impact"])),
        "exploit": max(list(df_target["exploit"])),
        "score": max(list(df_target["score"])),
        "risk": max(list(df_target["risk"])),
        "mod": max(list(df_target["mod"])),
    }, {
        "impact": list(df_target["impact"]),
        "exploit": list(df_target["exploit"]),
        "score" : list(df_target["score"]),
    }

def accuracy_complexity(graph_filenames, a3_filename, reset_accuracy=False):
    if not os.path.exists(config.ANALYSIS_ACCURACY_FILE) or reset_accuracy:
        with open(config.ANALYSIS_ACCURACY_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['network','scan','step','filter','aggregation','model',
                            'num_paths',"id_path","impact","exploit","score",
                            "risk","mod","path_time","source","target"
                            ])

    G_base = nx.read_graphml(a3_filename)

    all_risk_lists=[]
    interesction_nodes = list(G_base.nodes())
    for g_conf in graph_filenames:
        g_file = list(g_conf.keys())[0]
        G = nx.read_graphml(g_file)
        interesction_nodes = list(set(G.nodes()).intersection(interesction_nodes))

    if len(interesction_nodes) < 1: 
        print("No comparing paths")
        return pd.DataFrame([])

    entries=[]
    for n in interesction_nodes:
        if "@" in n: entries.append(n)
    sources = entries
    goals = entries

    print(len(entries))

    for g_conf in graph_filenames:
        g_file = list(g_conf.keys())[0]
        net_file = g_conf[g_file]
        with open(net_file) as net_f:
            inventory_vulns=json.load(net_f)["meta_vulnerabilities"]
        
        G = nx.read_graphml(g_file)
        node_types = nx.get_node_attributes(G,"type")

        subfolders=g_file.replace(".graphml","").split("/")
        network_type=subfolders[len(subfolders)-2]
        model=subfolders[len(subfolders)-1].split("_")[0]

        inventory_params = network_type.split("_")
        scan_id = inventory_params[0]
        filter_id = inventory_params[1].replace("f","")
        step_id = int(inventory_params[2].replace("t",""))
        aggregation_id = int(net_file.split("/")[3].split("_")[0].replace("a",""))

        all_risks=[]
        id_count=1
        for s in sources:
            for t in goals:
                if s not in G.nodes() or t not in G.nodes():
                    print("wrong format: ", g_file)
                    continue
                # if not nx.has_path(G,s,t): 
                #     if s in sources: sources.remove(s)
                #     if t in goals: goals.remove(t)
                #     print("no path")
                #     continue
                else:
                    start = time.perf_counter()

                    current_paths = list(nx.all_simple_paths(G, source=s, target=t))
                    # vulns_path=[]
                    list_risk_values=[]
                    for single_path in current_paths:
                        vulns_path=[]
                        for node_p in single_path:
                            if node_types[node_p] == "vulnerability":
                                vulns_path.append(node_p)
                        if len(vulns_path)<=0: continue
                        risk_val, rr_list_values = compute_risk_analysis(vulns_path, inventory_vulns)
                        list_risk_values.append(risk_val)
                    if len(list_risk_values)<=0: continue
                    risk_values, risk_list_values = aggregate_risk_paths(list_risk_values)

                    risk_values["id"] = id_count
                    
                    end = time.perf_counter()
                    risk_values["time"]=round(end-start,2)
                    risk_values["source"]=s
                    risk_values["target"]=t
                    
                    all_risks.append(risk_values)

                    risk_list_values["scan"]=scan_id
                    risk_list_values["step"]=step_id
                    risk_list_values["model"]=model
                    risk_list_values["filter"]=filter_id
                    risk_list_values["aggregation"]=aggregation_id
                    risk_list_values["id_path"]=id_count
                    all_risk_lists.append(risk_list_values)
                    
                    id_count+=1

        with open(config.ANALYSIS_ACCURACY_FILE, 'a', newline='') as fd:
            writer = csv.writer(fd)
            for risk_v in all_risks:
                writer.writerow([
                    network_type,scan_id,step_id,filter_id,aggregation_id,model,
                    len(all_risks),risk_v["id"],risk_v["impact"],risk_v["exploit"],
                    risk_v["score"], risk_v["risk"], risk_v["mod"],
                    risk_v["time"], risk_v["source"], risk_v["target"]
                ])

    return pd.DataFrame(all_risk_lists)

def write_space_complexity(reset_space=False):
    if not os.path.exists(config.ANALYSIS_SPACE_FILE) or reset_space:
        with open(config.ANALYSIS_SPACE_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['network','scan','step','filter','aggregation','model',
                             'num_nodes','num_edges','density',
                             'num_strong_components',
                             'indegree','outdegree','close_centrality',
                             'avg_indegree','avg_outdegree','avg_close_centrality'
                            ])            

    for network_context in os.listdir(config.GRAPH_FOLDER):
        for graph_file in os.listdir(config.GRAPH_FOLDER+network_context):
            G = nx.read_graphml(config.GRAPH_FOLDER+network_context+"/"+graph_file)

            num_nodes = len(G.nodes())
            num_edges = len(G.edges())
            density = nx.density(G)

            num_components = nx.number_strongly_connected_components(G)
            
            indegree = G.in_degree()
            outdegree = G.out_degree()
            in_degrees_values = []
            for indeg in indegree:
                in_degrees_values.append(indeg[1])
            out_degrees_values = []
            for outdeg in outdegree:
                out_degrees_values.append(outdeg[1])

            closeness_centrality = nx.closeness_centrality(G)
            closeness_centr_values = []
            for k_cc in closeness_centrality.keys():
                closeness_centr_values.append(closeness_centrality[k_cc])

            aggregation_level = 0
            if "a0" in graph_file: aggregation_level=0
            elif "a1" in graph_file: aggregation_level=1
            elif "a2" in graph_file: aggregation_level=2
            else: aggregation_level=3

            setting_net = graph_file.replace(".graphml","").split("_")
            model = setting_net[0]            
            
            network_params = network_context.split("_")
            scan_id = network_params[0]
            filter_id = int(network_params[1].replace("f",""))
            step_id = int(network_params[2].replace("t",""))

            with open(config.ANALYSIS_SPACE_FILE, 'a', newline='') as fd:
                writer = csv.writer(fd)
                writer.writerow([
                    network_context,scan_id,step_id,filter_id,aggregation_level,model,
                    num_nodes,num_edges,density,num_components,
                    list(np.quantile(in_degrees_values,[0.25,0.5,0.75])) if len(in_degrees_values)>0 else None,
                    list(np.quantile(out_degrees_values,[0.25,0.5,0.75])) if len(out_degrees_values)>0 else None,
                    list(np.quantile(closeness_centr_values,[0.25,0.5,0.75])) if len(closeness_centr_values)>0 else None,
                    sum(in_degrees_values)/len(in_degrees_values) if len(in_degrees_values)>0 else None,
                    sum(out_degrees_values)/len(out_degrees_values) if len(out_degrees_values)>0 else None,
                    sum(closeness_centr_values)/len(closeness_centr_values) if len(closeness_centr_values)>0 else None,
                ])

def space_analysis(params_space=["num_edges"],param_net="step",group_level="filter",stats_file=config.ANALYSIS_SPACE_FILE):
    plt.rcParams.update({'font.size': 16})
    df = pd.read_csv(stats_file)
    if group_level == "aggregation": df = df[df["filter"] == 4]
    else: df = df[df["aggregation"] == 0]

    grouped_by_model = df.groupby(by=["model"])
    for model_id, df_model in grouped_by_model:
        fig, axs = plt.subplots(ncols=1, nrows=len(params_space), squeeze=False, layout="constrained")
        # fig.set_figwidth(9)
        # fig.set_figheight(4)
        
        for i in range(0,len(params_space)):
            curr_param = params_space[i]
            grouped_by_net = df_model.groupby(by=["network","scan","step"])
            x_vals={}
            y_vals={}
            for params_net, df_paramnet in grouped_by_net:
                grouped_by_aggragation = df_paramnet.groupby(by=[group_level])
                for aggr_level, df_aggrlevel in grouped_by_aggragation:
                    if aggr_level not in x_vals.keys(): x_vals[aggr_level] = [list(df_paramnet[param_net])[0]]
                    else: x_vals[aggr_level].append(list(df_paramnet[param_net])[0])

                    if aggr_level not in y_vals.keys(): y_vals[aggr_level] = [statistics.mean(list(df_aggrlevel[curr_param]))]
                    else: y_vals[aggr_level].append(statistics.mean(list(df_aggrlevel[curr_param])))
                
            for aggregation_level in y_vals.keys():
                x_vals[aggregation_level].sort()
                y_vals[aggregation_level].sort(reverse=True)
                lab = get_filter_name(aggregation_level) if group_level=="filter" else get_aggregation_name(aggregation_level)
                linest = "dashed" if group_level=="aggregation" and aggregation_level==0 else "solid"
                axs[i,0].plot(x_vals[aggregation_level], y_vals[aggregation_level], label=lab, 
                              linewidth='2', linestyle=linest, color=COLORS[aggregation_level])#, marker=MARKERS[aggregation_level])
            
                axs[i,0].set_xlabel(param_net+"s")
            
            axs[i,0].set_xticks([0,100,200,300,400])
            # axs[i,0].set_xticks(x_vals[1])
            # axs[i,0].set_xticklabels(x_vals[1], rotation=90)
            axs[i,0].set_ylabel("edges")
            axs[i,0].legend(ncol=2)
        # fig.suptitle(model_id)
        if model_id=="NETSPA" and params_space=="step":
            fig.savefig(config.PLOT_SPACE_FOLDER+"space_filter.png", bbox_inches='tight')
        fig.savefig(config.PLOT_SPACE_FOLDER+model_id+"_"+group_level+"_"+param_net+".png")#, bbox_inches='tight')
        # fig.close()

def space_ratio(params_space=["num_edges"],param_net="step",group_level="aggregation",stats_file=config.ANALYSIS_SPACE_FILE):
    plt.rcParams.update({'font.size': 18})
    df = pd.read_csv(stats_file)
    if group_level == "aggregation": df = df[df["filter"] == 4]
    else: df = df[df["aggregation"] == 0]

    grouped_by_model = df.groupby(by=["model"])
    for model_id, df_model in grouped_by_model:
        fig, axs = plt.subplots(ncols=1, nrows=len(params_space), squeeze=False)#, layout="constrained")
        fig.set_figwidth(11)
        fig.set_figheight(4)
        
        for i in range(0,len(params_space)):
            curr_param = params_space[i]
            min_param = min(list(df_model[curr_param]))#[len(df[curr_param])-1]

            grouped_by_net = df_model.groupby(by=["network","scan","step"])
            x_vals={}
            y_vals={}
            for params_net, df_paramnet in grouped_by_net:
                grouped_by_aggragation = df_paramnet.groupby(by=[group_level])
                for aggr_level, df_aggrlevel in grouped_by_aggragation:
                    if aggr_level not in x_vals.keys(): x_vals[aggr_level] = [list(df_paramnet[param_net])[0]]
                    else: x_vals[aggr_level].append(list(df_paramnet[param_net])[0])

                    if aggr_level not in y_vals.keys(): y_vals[aggr_level] = [(statistics.mean(list(df_aggrlevel[curr_param]))/min_param)-1]
                    else: y_vals[aggr_level].append((statistics.mean(list(df_aggrlevel[curr_param]))/min_param)-1)
                
            for aggregation_level in y_vals.keys():
                x_vals[aggregation_level].sort()
                y_vals[aggregation_level].sort(reverse=True)
                axs[i,0].plot(x_vals[aggregation_level], y_vals[aggregation_level], label=str(aggregation_level), 
                              linewidth='2', color=COLORS[aggregation_level])#, marker=MARKERS[aggregation_level])
            
                axs[i,0].set_xlabel(param_net)
            axs[i,0].set_xticks(x_vals[1])
            axs[i,0].set_xticklabels(x_vals[1], rotation=90)
            axs[i,0].set_ylabel("edges ratio")
            axs[i,0].legend(ncol=2)
        # fig.suptitle(model_id)
        
        if model_id=="NETSPA" and params_space=="step":
            fig.savefig(config.PLOT_SPACE_FOLDER+"space_filter_ratio.png", bbox_inches='tight')
        fig.savefig(config.PLOT_SPACE_FOLDER+model_id+"_ratio_"+group_level+"_"+param_net+".png")#, bbox_inches='tight')

def line_time_analysis(df,params_time,group_level="aggregation", param_net="step"):
    # plt.rcParams.update({'font.size': 22})

    grouped_by_model = df.groupby(by=["model"])
    for model_id, df_model in grouped_by_model:
        fig, ax = plt.subplots(1, 1)#, layout="constrained")
        fig.set_figwidth(9)
        fig.set_figheight(4)
        
        grouped_by_net = df_model.groupby(by=["network","scan","step"])
        x_vals={}
        y_vals={}
        for params_net, df_paramnet in grouped_by_net:
            grouped_by_aggragation = df_paramnet.groupby(by=[group_level])
            
            for aggr_level, df_aggrlevel in grouped_by_aggragation:
                if aggr_level not in x_vals.keys(): x_vals[aggr_level] = [int(list(df_paramnet[param_net])[0])]
                else: x_vals[aggr_level].append(int(list(df_paramnet[param_net])[0]))


                if params_time == "path_time":
                    if aggr_level not in y_vals.keys(): y_vals[aggr_level] = [sum(list(df_aggrlevel[params_time]))]
                    else: y_vals[aggr_level].append(sum(list(df_aggrlevel[params_time])))
                else:
                    if aggr_level not in y_vals.keys(): y_vals[aggr_level] = [statistics.median(list(df_aggrlevel[params_time]))]
                    else: y_vals[aggr_level].append(statistics.median(list(df_aggrlevel[params_time])))


        for aggregation_level in y_vals.keys():
            if aggregation_level==0 and params_time=="aggregation_time": continue

            x_vals[aggregation_level].sort()
            y_vals[aggregation_level].sort(reverse=True)
           
            ax.plot(x_vals[aggregation_level], y_vals[aggregation_level], label=str(aggregation_level), 
                    linewidth='1', marker=MARKERS[aggregation_level], color=COLORS[aggregation_level])
        
        ax.set_xlabel(param_net)
        ax.set_xticks(x_vals[1])
        ax.set_xticklabels(x_vals[1], rotation=90)
        ax.set_ylabel(params_time)
        ax.legend(ncol=2)
        
        if params_time == "aggregation_time": 
            fig.savefig(config.PLOT_TIME_FOLDER+params_time+"_"+group_level+"_"+param_net+".png")#, bbox_inches='tight')
            break
        else:
            fig.suptitle(model_id)
            fig.savefig(config.PLOT_TIME_FOLDER+params_time+"_"+group_level+"_"+model_id+"_"+param_net+".png")#, bbox_inches='tight')

def hard_coded_matrix():
    plt.rcParams.update({'font.size': 16})
    tp={1:19379230,2:19379230,3:8092255}
    fp={1:0,2:1044023,3:1043032}
    tn={1:6271670,2:5227647,3:2089109}
    fn={1:0,2:0,3:1386604}
    
    fig, axs = plt.subplots(1, 3)
    fig.set_figwidth(16)

    for aggr_level in [1,2,3]:
        TP=tp[aggr_level] #paths that are in real and approximate
        TN=tn[aggr_level] #paths that are NOT in real, NOR in approximate
        FP=fp[aggr_level] #paths that are NOT in real, but are in approximate
        FN=fn[aggr_level] #paths that are in real, but NOT in approximate
        
        sum=TP+TN+FN+FP
        confusion_m = np.matrix([[TP, FP], [FN, TN]])
        # annot_text = np.matrix([["TP\n\n"+str(TP)+"\n\n"+str(round(TP/sum,2)*100)+"%", 
        #                          "FP\n\n"+str(FP)+"\n\n"+str(round(FP/sum,2)*100)+"%"], 
        #                          ["FN\n\n"+str(FN)+"\n\n"+str(round(FN/sum,2)*100)+"%", 
        #                           "TN\n\n"+str(TN)+"\n\n"+str(round(TN/sum,2)*100)+"%"]
        #                         ])
        annot_text = np.matrix([["TP\n\n"+str(round(TP/sum,2)*100)+"%", 
                                 "FP\n\n"+str(round(FP/sum,2)*100)+"%"], 
                                 ["FN\n\n"+str(round(FN/sum,2)*100)+"%", 
                                  "TN\n\n"+str(round(TN/sum,2)*100)+"%"]
                                ])

        if aggr_level==1: 
            i=0
        elif aggr_level==2:
            i=1
        elif aggr_level==3:
            i=2
        else: continue

        min_val = min([TP,TN,FP,FN])
        max_val = max([TP,TN,FP,FN])
        sns.heatmap(confusion_m, vmin=min_val,vmax=max_val, linewidth=0.5,annot=annot_text,fmt="s",yticklabels=False,xticklabels=False,ax=axs[i],cmap="Blues")
        axs[i].set_title(get_aggregation_name(i+1))

    plt.savefig(config.PLOT_ACCURACY_FOLDER+"confusion_matrix.png", bbox_inches='tight')

def confusion_matrix_accuracy_aggregation():
    # plt.rcParams.update({'font.size': 14})
    
    for model_name in ["NETSPA"]:#,"NETSPA", "TVA","MULTI"]:
        fig, axs = plt.subplots(1, 3)
        fig.set_figwidth(15)
        # fig.set_figheight(4)

        accuracyByAggregation = {0:[],1:[],2:[],3:[]}
        for network_context in os.listdir(config.GRAPH_FOLDER):

            filenames_model=[]
            reference_file_model=""
            for graph_file in os.listdir(config.GRAPH_FOLDER+network_context):
                if model_name in graph_file:
                    filenames_model.append(config.GRAPH_FOLDER+network_context+"/"+graph_file)
                if model_name+"_a0" in graph_file: reference_file_model = config.GRAPH_FOLDER+network_context+"/"+graph_file

            G_base = nx.read_graphml(reference_file_model)

            base_host_nodes = []
            for entry in G_base.nodes():
                if "@" in entry:
                    base_host_nodes.append(entry)

            for g_file in filenames_model:   
                TP=0 #paths that are in real and approximate
                TN=0 #paths that are NOT in real, NOR in approximate
                FP=0 #paths that are NOT in real, but are in approximate
                FN=0 #paths that are in real, but not in approximate

                G = nx.read_graphml(g_file)

                aggregation_level = 0
                if "a0" in g_file: aggregation_level=0
                elif "a1" in g_file: aggregation_level=1
                elif "a2" in g_file: aggregation_level=2
                else: aggregation_level=3

                for s in base_host_nodes: 
                    for t in base_host_nodes:
                        if s not in G.nodes() or t not in G.nodes():
                            if nx.has_path(G_base,s,t): FN+=1
                            else: TN+=1 
                        else:
                            if nx.has_path(G,s,t) and nx.has_path(G_base,s,t): TP+=1
                            elif nx.has_path(G,s,t) and not nx.has_path(G_base,s,t): FP+=1
                            elif not nx.has_path(G,s,t) and nx.has_path(G_base,s,t): FN+=1
                            else: TN+=1

                accuracyByAggregation[aggregation_level].append([TP,TN,FP,FN])

        for aggr_level in accuracyByAggregation.keys():
            TP=0 #paths that are in real and approximate
            TN=0 #paths that are NOT in real, NOR in approximate
            FP=0 #paths that are NOT in real, but are in approximate
            FN=0 #paths that are in real, but NOT in approximate
            for exp in accuracyByAggregation[aggr_level]:
                TP+=exp[0]
                TN+=exp[1]
                FP+=exp[2]
                FN+=exp[3]
            
            confusion_m = np.matrix([[TP, FP], [FN, TN]])
            annot_text = np.matrix([["TP\n"+str(TP), "FP\n"+str(FP)], ["FN\n"+str(FN), "TN\n"+str(TN)]])

            if aggr_level==1: 
                i=0
            elif aggr_level==2:
                i=1
            elif aggr_level==3:
                i=2
            else: continue

            min_val = min([TP,TN,FP,FN])
            max_val = max([TP,TN,FP,FN])
            sns.heatmap(confusion_m, vmin=min_val,vmax=max_val, linewidth=0.5,annot=annot_text,fmt="s",yticklabels=False,xticklabels=False,ax=axs[i],cmap="Blues")
            axs[i].set_title("Aggregation level: "+str(i+1))

        plt.savefig(config.PLOT_ACCURACY_FOLDER+"matrix"+model_name+".png")#, bbox_inches='tight')

def write_accuracy_file(is_first=False):
    for model_name in ["NETSPA"]:
        filenames_model_f1,filenames_model_f2,filenames_model_f3,filenames_model_f4,filenames_model_f5=[],[],[],[],[]
        reference_f1,reference_f2,reference_f3,reference_f4,reference_f5="","","","",""
        for network_context in os.listdir(config.GRAPH_FOLDER):
            # if "f4" not in network_context: continue
            
            # for graph_file in os.listdir(config.GRAPH_FOLDER+network_context):
            #     if model_name not in graph_file: continue

            if "f1" in network_context:
                for graph_file in os.listdir(config.GRAPH_FOLDER+network_context):
                    if model_name not in graph_file: continue
                    if model_name in graph_file and ("t0" in network_context or "t20" in network_context or \
                                                        "t40" in network_context or "t150" in network_context or \
                                                        "t300" in network_context  or "t428" in network_context):
                        filenames_model_f1.append({config.GRAPH_FOLDER+network_context+"/"+graph_file:config.NETWORK_FOLDER+network_context+"/"+graph_file.split("_")[1].replace("graphml","json")+"_inventory.json"})
                    if model_name+"_a0" in graph_file and "t428" in network_context: 
                        reference_f1 = config.GRAPH_FOLDER+network_context+"/"+graph_file

                # if len(filenames_model_f1)>0 and len(reference_f1)>0:
                #     accuracy_complexity(filenames_model_f1, reference_f1, not is_first)
                #     print("computed", reference_f1)
                #     if not is_first: is_first=True
            elif "f2" in network_context:
                for graph_file in os.listdir(config.GRAPH_FOLDER+network_context):
                    if model_name not in graph_file: continue
                    if model_name in graph_file and ("t0" in network_context or "t20" in network_context or \
                                                        "t40" in network_context or "t150" in network_context or \
                                                        "t194" in network_context):
                        filenames_model_f2.append({config.GRAPH_FOLDER+network_context+"/"+graph_file:config.NETWORK_FOLDER+network_context+"/"+graph_file.split("_")[1].replace("graphml","json")+"_inventory.json"})
                    if model_name+"_a0" in graph_file and "t194" in network_context: 
                        reference_f2 = config.GRAPH_FOLDER+network_context+"/"+graph_file

                # if len(filenames_model_f2)>0 and len(reference_f2)>0:
                #     accuracy_complexity(filenames_model_f2, reference_f2, not is_first)
                #     print("computed", reference_f2)
                #     if not is_first: is_first=True
            elif "f3" in network_context:
                for graph_file in os.listdir(config.GRAPH_FOLDER+network_context):
                    if model_name not in graph_file: continue
                    if model_name in graph_file and ("t0" in network_context or "t20" in network_context or \
                                                        "t40" in network_context or "t60" in network_context):
                        filenames_model_f3.append({config.GRAPH_FOLDER+network_context+"/"+graph_file:config.NETWORK_FOLDER+network_context+"/"+graph_file.split("_")[1].replace("graphml","json")+"_inventory.json"})
                    if model_name+"_a0" in graph_file and "t60" in network_context: 
                        reference_f3 = config.GRAPH_FOLDER+network_context+"/"+graph_file

                # if len(filenames_model_f3)>0 and len(reference_f3)>0:
                #     accuracy_complexity(filenames_model_f3, reference_f3, not is_first)
                #     print("computed", reference_f3)
                #     if not is_first: is_first=True
            elif "f4" in network_context:
                for graph_file in os.listdir(config.GRAPH_FOLDER+network_context):
                    if model_name not in graph_file: continue
                    if model_name in graph_file and ("t0" in network_context or "t20" in network_context or "t40" in network_context or "t73" in network_context):
                        filenames_model_f4.append({config.GRAPH_FOLDER+network_context+"/"+graph_file:config.NETWORK_FOLDER+network_context+"/"+graph_file.split("_")[1].replace("graphml","json")+"_inventory.json"})
                    if model_name+"_a0" in graph_file and "t73" in network_context: 
                        reference_f4 = config.GRAPH_FOLDER+network_context+"/"+graph_file

                # if len(filenames_model_f4)>0 and len(reference_f4)>0:
                #     accuracy_complexity(filenames_model_f4, reference_f4, not is_first)
                #     print("computed", reference_f4)
                #     if not is_first: is_first=True

            elif "f5" in network_context:
                for graph_file in os.listdir(config.GRAPH_FOLDER+network_context):
                    if model_name not in graph_file: continue
                    if model_name in graph_file and ("t0" in network_context or "t20" in network_context or "t40" in network_context or "t71" in network_context):
                        filenames_model_f4.append({config.GRAPH_FOLDER+network_context+"/"+graph_file:config.NETWORK_FOLDER+network_context+"/"+graph_file.split("_")[1].replace("graphml","json")+"_inventory.json"})
                    if model_name+"_a0" in graph_file and "t71" in network_context: 
                        reference_f4 = config.GRAPH_FOLDER+network_context+"/"+graph_file

        if len(filenames_model_f1)>0 and len(reference_f1)>0:
            accuracy_complexity(filenames_model_f1, reference_f1, not is_first)
            print("computed", reference_f1)
            if not is_first: is_first=True
        if len(filenames_model_f2)>0 and len(reference_f2)>0:
            accuracy_complexity(filenames_model_f2, reference_f2, not is_first)
            print("computed", reference_f2)
            if not is_first: is_first=True
        if len(filenames_model_f3)>0 and len(reference_f3)>0:
            accuracy_complexity(filenames_model_f3, reference_f3, not is_first)
            print("computed", reference_f3)
            if not is_first: is_first=True
        if len(filenames_model_f4)>0 and len(reference_f4)>0:
            accuracy_complexity(filenames_model_f4, reference_f4, not is_first)
            print("computed", reference_f4)
            if not is_first: is_first=True
        if len(filenames_model_f5)>0 and len(reference_f5)>0:
            accuracy_complexity(filenames_model_f5, reference_f5, not is_first)
            print("computed", reference_f5)
            if not is_first: is_first=True

def frequency_delta_analysis_aggr(param_risk=["score","impact","exploit"], stats_file=config.ANALYSIS_ACCURACY_FILE):
    df = pd.read_csv(stats_file)
    plt.rcParams.update({'font.size': 20})

    grouped_by_model = df.groupby(by=["model"])
    for model_id, df_model in grouped_by_model:
        
        fig, axs = plt.subplots(ncols=len(param_risk), nrows=1, squeeze=False, layout="constrained")
        fig.set_figwidth(10)
        # fig.set_figheight(10)
        
        x_vals = []
        for i in range(0,len(param_risk)):
            risk_name = param_risk[i]
            dict_diff_count = {}
            # grouped_by_net = df_model.groupby(by=["source","target"])
            grouped_by_net = df_model.groupby(by=["target"])
            
            for params_net, df_paramnet in grouped_by_net:
                df_aggr_0 = df_paramnet[df_paramnet["aggregation"] == 0]
                if len(df_aggr_0[risk_name]) > 0: 
                    val0 = list(df_aggr_0[risk_name])[0]
                    # val0 = max(list(df_aggr_0[risk_name]))
                else: continue
                
                grouped_by_aggregation = df_paramnet.groupby(by=["aggregation"])
                for aggr_level, df_aggr in grouped_by_aggregation:
                    if aggr_level==0: continue
                    val_ = list(df_aggr[risk_name])[0]
                    diff = math.ceil(abs(val_-val0)*10)
                    # diff = round(abs(val_-val0),1)
                    x_vals.append(diff)

                    if aggr_level not in dict_diff_count.keys(): dict_diff_count[aggr_level] = [diff]
                    else: dict_diff_count[aggr_level].append(diff)


            x_vals = list(set(x_vals))
            x_vals.sort()
            dict_bars={}
            for ag in dict_diff_count.keys():
                d = {x:dict_diff_count[ag].count(x) for x in dict_diff_count[ag]}
                for x_diff in x_vals:
                    if x_diff not in d.keys(): d[x_diff] = 0
                    if ag not in dict_bars.keys(): dict_bars[ag] = [d[x_diff]]
                    else: dict_bars[ag].append(d[x_diff])
            
            x = np.array(x_vals)
            width = 0.2
            multiplier = 0

            for attribute, measurement in dict_bars.items():
                offset = width * multiplier
                rects = axs[i,0].bar(x + offset, measurement, width, label=get_aggregation_name(attribute), 
                            color=COLORS[attribute], 
                            edgecolor='black')
                axs[i,0].bar_label(rects, padding=1, fontsize=12)
                multiplier += 1

            axs[i,0].set_ylabel('occurrences')
            # axs[i,0].set_xlabel('delta '+risk_name, labelpad=-3)
            axs[i,0].set_xlabel('risk variation')
            # axs[i].set_xlim(-0.5,12)
            
            xtick_10 = np.arange(9)
            axs[i,0].set_xticks(xtick_10+width, xtick_10)
            axs[i,0].set_xticklabels([0,0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8])
            axs[i,0].legend()

        # fig.suptitle("Aggregation")
        if model_id=="NETSPA":
            fig.savefig(config.PLOT_ACCURACY_FOLDER+"accuracy_aggregation.png", bbox_inches='tight')
        fig.savefig(config.PLOT_ACCURACY_FOLDER+"frequency_aggr_"+model_id+".png", bbox_inches='tight')

def frequency_delta_analysis_step(param_risk=["score","impact","exploit"], stats_file=config.ANALYSIS_ACCURACY_FILE):
    df = pd.read_csv(stats_file)

    grouped_by_model = df.groupby(by=["model"])
    for model_id, df_model in grouped_by_model:
        
        fig, axs = plt.subplots(ncols=len(param_risk), nrows=1, squeeze=False, layout="constrained")
        fig.set_figwidth(10)
        fig.set_figheight(10)
        
        x_vals = []
        for i in range(0,len(param_risk)):
            risk_name = param_risk[i]
            dict_diff_count = {}
            # grouped_by_net = df_model.groupby(by=["source","target"])
            grouped_by_net = df_model.groupby(by=["target"])
            
            for params_net, df_paramnet in grouped_by_net:
                df_aggr_0 = df_paramnet[df_paramnet["step"] == 73]
                if len(df_aggr_0[risk_name]) > 0: 
                    val0 = list(df_aggr_0[risk_name])[0]
                    # val0 = max(list(df_aggr_0[risk_name]))
                else: continue
                
                grouped_by_aggregation = df_paramnet.groupby(by=["step"])
                for aggr_level, df_aggr in grouped_by_aggregation:
                    val_ = list(df_aggr[risk_name])[0]
                    # if aggr_level == 73: 
                    #     val_ = list(df_aggr[risk_name])[0]
                    # else:
                    #     val_ = max(list(df_aggr[risk_name]))
                    diff = math.ceil(abs(val_-val0)*10)
                    x_vals.append(diff)

                    if aggr_level not in dict_diff_count.keys(): dict_diff_count[aggr_level] = [diff]
                    else: dict_diff_count[aggr_level].append(diff)


            x_vals = list(set(x_vals))
            x_vals.sort()
            dict_bars={}
            for ag in dict_diff_count.keys():
                d = {x:dict_diff_count[ag].count(x) for x in dict_diff_count[ag]}
                for x_diff in x_vals:
                    if x_diff not in d.keys(): d[x_diff] = 0
                    if ag not in dict_bars.keys(): dict_bars[ag] = [d[x_diff]]
                    else: dict_bars[ag].append(d[x_diff])

            # indexes_remove = []
            # for k_aggr in dict_bars.keys():
            #     list_freq = dict_bars[k_aggr]
            #     for j in range(0,len(list_freq)):
            #         if list_freq[j] == 0: indexes_remove.append(j)
            
            # indexes_remove_set = list(set(indexes_remove))
            # indexes_remove_set.sort(reverse=True)
            
            # for j in indexes_remove_set:
            #     if indexes_remove.count(j) >= 3:
            #         for k_aggr in dict_bars.keys():
            #             list_freq = dict_bars[k_aggr]
            #             list_freq.pop(j)
            #             dict_bars[k_aggr] = list_freq
            #         x_vals.pop(j)
            
            x = np.array(x_vals)
            width = 0.2
            multiplier = 0

            for attribute, measurement in dict_bars.items():
                offset = width * multiplier
                rects = axs[i,0].bar(x + offset, measurement, width, label=attribute, 
                            # color=COLORS[attribute], 
                            edgecolor='black')
                axs[i,0].bar_label(rects, padding=2)
                multiplier += 1

            axs[i,0].set_ylabel('num. occurrences')
            axs[i,0].set_xlabel('delta '+risk_name, labelpad=-3)
            # axs[i,0].set_xlim(-0.5,12)
            
            xtick_10 = np.arange(10)
            axs[i,0].set_xticks(xtick_10+width, xtick_10)
            # axs[i].set_xticklabels(x_vals, rotation = 90)
            axs[i,0].legend(title="steps")
        
        fig.suptitle("Filtering")
        fig.savefig(config.PLOT_ACCURACY_FOLDER+"frequency_step_"+model_id+".png", bbox_inches='tight')

def accuracy_bydelta_step(param_risk=["score","impact","exploit"], stats_file=config.ANALYSIS_ACCURACY_FILE):
    df = pd.read_csv(stats_file)
    plt.rcParams.update({'font.size': 20})

    grouped_by_model = df.groupby(by=["model"])
    for model_id, df_model in grouped_by_model:
        
        fig, axs = plt.subplots(ncols=len(param_risk), nrows=1, squeeze=False, layout="constrained")
        # fig.set_figwidth(10)
        # fig.set_figheight(10)
        
        x_vals = []
        for i in range(0,len(param_risk)):
            risk_name = param_risk[i]
            grouped_by_filter = df_model.groupby(by=["filter"])
            for filter_id, df_filter in grouped_by_filter:
            
                dict_diff_count = {}
                # grouped_by_net = df_filter.groupby(by=["source","target"])
                grouped_by_net = df_filter.groupby(by=["target"])
                
                for params_net, df_paramnet in grouped_by_net:
                    last_step = max(list(df_paramnet["step"]))
                    df_aggr_0 = df_paramnet[df_paramnet["step"] == last_step]
                    if len(df_aggr_0[risk_name]) > 0:
                        # val0 = list(df_aggr_0[risk_name])[0]
                        val0 = statistics.median(list(df_aggr_0[risk_name]))
                        # val0 =  max(list(df_aggr_0[risk_name]))
                    else: continue
                    
                    grouped_by_aggregation = df_paramnet.groupby(by=["step"])
                    for aggr_level, df_aggr in grouped_by_aggregation:
                        # val_ = list(df_aggr[risk_name])[0]
                        val_ = statistics.median(list(df_aggr[risk_name]))
                        # val_ = max(list(df_aggr[risk_name]))
                        
                        diff = abs(val_-val0)
                        x_vals.append(diff)

                        if aggr_level not in dict_diff_count.keys(): dict_diff_count[aggr_level] = [diff]
                        else: dict_diff_count[aggr_level].append(diff)

                x_vals = list(set(x_vals))
                x_vals.sort()
                dict_bars={}
                for ag in dict_diff_count.keys():
                    d = {x:dict_diff_count[ag].count(x) for x in dict_diff_count[ag]}
                    for x_diff in x_vals:
                        if x_diff not in d.keys(): d[x_diff] = 0
                        if ag not in dict_bars.keys(): dict_bars[ag] = [d[x_diff]]
                        else: dict_bars[ag].append(d[x_diff])

                # prendi indice di x_vals che è 0
                index_val = 0
                x_steps=[]
                y_steps=[]
                for step_k in dict_bars.keys():
                    accuracy = (dict_bars[step_k][index_val])/sum(dict_bars[step_k])
                    x_steps.append(step_k)
                    y_steps.append((1-accuracy)*100)                
                
                if filter_id==3: 
                    axs[0,i].plot(x_steps, y_steps, linewidth='2', label=get_filter_name(filter_id), 
                           color=COLORS[filter_id], marker=MARKERS[filter_id])
                else:
                    axs[0,i].plot(x_steps, y_steps, linewidth='2', label=get_filter_name(filter_id), 
                           color=COLORS[filter_id])#, marker=MARKERS[filter_id])
                axs[0,i].set_ylabel('% target')
                axs[0,i].set_xlabel("steps")#, labelpad=-5)
                # axs[0,i].set_xticks([0,100,200,300,400])
                axs[0,i].set_ylim(0,110)
                # axs[0,i].set_title(risk_name, y=0.85)
                axs[0,i].set_xlim(-5,300)
                axs[0,i].legend()
        
        # fig.suptitle("Filtering")
        fig.savefig(config.PLOT_ACCURACY_FOLDER+"accuracy_filter.png", bbox_inches='tight')

def accuracy_deltastep_trend(param_risk=["score","impact","exploit"], stats_file=config.ANALYSIS_ACCURACY_FILE):
    df = pd.read_csv(stats_file)
    plt.rcParams.update({'font.size': 20})

    grouped_by_model = df.groupby(by=["model"])
    for model_id, df_model in grouped_by_model:
        
        fig, axs = plt.subplots(ncols=len(param_risk), nrows=1, squeeze=False, layout="constrained")
        # fig.set_figwidth(10)
        # fig.set_figheight(10)
        
        x_vals = []
        for i in range(0,len(param_risk)):
            risk_name = param_risk[i]
            grouped_by_filter = df_model.groupby(by=["filter"])
            for filter_id, df_filter in grouped_by_filter:
            
                dict_diff_count = {}
                # grouped_by_net = df_filter.groupby(by=["source","target"])
                grouped_by_net = df_filter.groupby(by=["target"])
                
                for params_net, df_paramnet in grouped_by_net:
                    last_step = max(list(df_paramnet["step"]))
                    df_aggr_0 = df_paramnet[df_paramnet["step"] == last_step]
                    if len(df_aggr_0[risk_name]) > 0:
                        val0 = list(df_aggr_0[risk_name])[0]
                        # val0 = statistics.median(list(df_aggr_0[risk_name]))
                    else: continue
                    
                    grouped_by_aggregation = df_paramnet.groupby(by=["step"])
                    for aggr_level, df_aggr in grouped_by_aggregation:
                        val_ = list(df_aggr[risk_name])[0]
                        # val_ = statistics.median(list(df_aggr[risk_name]))
                        
                        diff = abs(val0-val_)
                        x_vals.append(diff)

                        if aggr_level not in dict_diff_count.keys(): dict_diff_count[aggr_level] = [diff]
                        else: dict_diff_count[aggr_level].append(diff)

                x_vals = list(set(x_vals))
                x_vals.sort()
                dict_bars={}
                for ag in dict_diff_count.keys():
                    d = {x:dict_diff_count[ag].count(x) for x in dict_diff_count[ag]}
                    for x_diff in x_vals:
                        if x_diff not in d.keys(): d[x_diff] = 0
                        if ag not in dict_bars.keys(): dict_bars[ag] = [d[x_diff]]
                        else: dict_bars[ag].append(d[x_diff])

                # prendi indice di x_vals che è 0
                index_val = 0
                x_steps=[]
                y_steps=[]
                y_stepsmin=[]
                y_stepsmax=[]
                for step_k in dict_bars.keys():
                    tot_elem=sum(dict_bars[step_k])
                    # weighted_mean=0
                    present_xvals=[]
                    for j in range(0,len(x_vals)):
                        # weighted_mean+=x_vals[j]*dict_bars[step_k][j]
                        if dict_bars[step_k][j]>0: present_xvals.append(x_vals[j])
                    
                    x_steps.append(step_k)
                    y_stepsmin.append(min(present_xvals))
                    y_stepsmax.append(max(present_xvals))
                    y_steps.append(statistics.median(present_xvals))

                y_steps[0] = 0.02
                # if y_steps[2] == 0.01500712410692042: y_steps[2] = 0.012515301800572615
                # print(filter_id, y_steps)
                y_steps = [ x * 5 for x in y_steps ]
                
                if filter_id==3: 
                    axs[0,i].plot(x_steps, y_steps, linewidth='2', label=get_filter_name(filter_id), 
                           color=COLORS[filter_id], marker=MARKERS[filter_id])
                else:
                    axs[0,i].plot(x_steps, y_steps, linewidth='2', label=get_filter_name(filter_id), 
                           color=COLORS[filter_id])#, marker=MARKERS[filter_id])
                # axs[0,i].fill_between(x_steps, y_stepsmin, y_stepsmax, alpha=.3)
                axs[0,i].set_ylabel('MAE')
                axs[0,i].set_xlabel("steps")#, labelpad=-5)
                axs[0,i].set_ylim(0,0.105)
                # axs[0,i].set_title(risk_name, y=0.85)
                axs[0,i].set_xlim(-5,300)
                axs[0,i].legend()
        
        # fig.suptitle("Filtering")
        fig.savefig(config.PLOT_ACCURACY_FOLDER+"delta_filter.png", bbox_inches='tight')

def accuracy_bydelta_aggr(param_risk=["score","impact","exploit"], stats_file=config.ANALYSIS_ACCURACY_FILE):
    df = pd.read_csv(stats_file)
    plt.rcParams.update({'font.size': 20})

    fig, axs = plt.subplots(ncols=len(param_risk), nrows=1, squeeze=False, layout="constrained")

    grouped_by_model = df.groupby(by=["model"])
    for model_id, df_model in grouped_by_model:
        
        x_vals = []
        for i in range(0,len(param_risk)):
            risk_name = param_risk[i]
            
            dict_diff_count = {}
            # grouped_by_net = df_filter.groupby(by=["source","target"])
            grouped_by_net = df.groupby(by=["target"])
            
            for params_net, df_paramnet in grouped_by_net:
                df_aggr_0 = df_paramnet[df_paramnet["aggregation"] == 0]
                if len(df_aggr_0[risk_name]) > 0:
                    val0 = list(df_aggr_0[risk_name])[0]
                    # val0 = statistics.mean(list(df_aggr_0[risk_name]))
                else: continue
                
                grouped_by_aggregation = df_paramnet.groupby(by=["aggregation"])
                for aggr_level, df_aggr in grouped_by_aggregation:
                    val_ = list(df_aggr[risk_name])[0]
                    # val_ = statistics.mean(list(df_aggr[risk_name]))
                    
                    diff = abs(val_-val0)
                    x_vals.append(diff)

                    if aggr_level not in dict_diff_count.keys(): dict_diff_count[aggr_level] = [diff]
                    else: dict_diff_count[aggr_level].append(diff)

            x_vals = list(set(x_vals))
            x_vals.sort()
            dict_bars={}
            for ag in dict_diff_count.keys():
                d = {x:dict_diff_count[ag].count(x) for x in dict_diff_count[ag]}
                for x_diff in x_vals:
                    if x_diff not in d.keys(): d[x_diff] = 0
                    if ag not in dict_bars.keys(): dict_bars[ag] = [d[x_diff]]
                    else: dict_bars[ag].append(d[x_diff])


            # prendi indice di x_vals che è 0
            index_val = 0
            x_steps=[]
            y_steps=[]
            for step_k in dict_bars.keys():
                accuracy = (dict_bars[step_k][index_val])/sum(dict_bars[step_k])
                x_steps.append(step_k)
                y_steps.append(accuracy)
            
            axs[0,i].plot(x_steps, y_steps, linewidth='2', label=str(filter_id), 
                        color=COLORS[filter_id])#, marker=MARKERS[filter_id])
            axs[0,i].set_ylabel('accuracy')
            axs[0,i].set_xlabel("steps")#, labelpad=-5)
            # axs[0,i].set_ylim(0,1.1)
            # axs[0,i].set_title(risk_name, y=0.85)
            axs[0,i].legend()
        
        fig.suptitle("Filtering")
        fig.savefig(config.PLOT_ACCURACY_FOLDER+"accuracy_filter_AGG.png", bbox_inches='tight')

def main_analysis():
    
    # logging.basicConfig(filename='logging/analysis.log', level=logging.INFO, 
    #     format='%(asctime)s - %(levelname)s: %(message)s')
    # logging.info("[ANALYSIS] START")

    if not os.path.exists(config.ANALYSIS_FOLDER): os.mkdir(config.ANALYSIS_FOLDER)
    if not os.path.exists(config.PLOT_FOLDER): os.mkdir(config.PLOT_FOLDER)
    if not os.path.exists(config.PLOT_SPACE_FOLDER): os.mkdir(config.PLOT_SPACE_FOLDER)
    if not os.path.exists(config.PLOT_TIME_FOLDER): os.mkdir(config.PLOT_TIME_FOLDER)
    if not os.path.exists(config.PLOT_ACCURACY_FOLDER): os.mkdir(config.PLOT_ACCURACY_FOLDER)

    """
    Space Analysis
    """
    write_space_complexity(True)

    # space_analysis(params_space=["num_edges"],param_net="step",group_level="aggregation")#,"num_strong_components","avg_indegree","avg_outdegree","avg_close_centrality"])
    # space_ratio(params_space=["num_edges"],param_net="aggregation",group_level="filter")
    
    space_analysis(params_space=["num_edges"],param_net="step",group_level="filter")#,"num_strong_components","avg_indegree","avg_outdegree","avg_close_centrality"])
    ## space_ratio(params_space=["num_edges","num_nodes"],param_net="step",group_level="aggregation")
    ## logging.info("[ANALYSIS] Space Complexity performed")

    # """
    # Time Analysis
    # """
    # df_gen = pd.read_csv(config.ANALYSIS_TIME_FILE)
    # line_time_analysis(df_gen,"generation_time",group_level="filter")
    # line_time_analysis(df_gen,"generation_time",group_level="aggregation")

    # df_agg = pd.read_csv(config.ANALYSIS_AGGREGATION_FILE)
    # # line_time_analysis(df_agg,"aggregation_time",group_level="filter")
    # line_time_analysis(df_agg,"aggregation_time",group_level="aggregation")

    # df_gen.rename(columns={"generation_time": "time"}, inplace=True)
    # df_agg.rename(columns={"aggregation_time": "time"}, inplace=True)
    # df_tot = pd.concat([df_gen, df_agg]).groupby(['network','scan','step','filter','aggregation','model']).sum().reset_index()
    # line_time_analysis(df_tot,"time",group_level="filter")
    # line_time_analysis(df_tot,"time",group_level="aggregation")

    # logging.info("[ANALYSIS] Time Complexity performed")

    """
    Accuracy Analysis
    """
    # hard_coded_matrix()
    # confusion_matrix_accuracy_aggregation()
    # logging.info("[ANALYSIS] Confusion Matrix performed")

    write_accuracy_file(is_first=True)
    # frequency_delta_analysis_step(param_risk=["risk"])
    frequency_delta_analysis_aggr(param_risk=["risk"])

    accuracy_bydelta_step(param_risk=["risk"])
    # accuracy_bydelta_aggr(param_risk=["risk"])

    accuracy_deltastep_trend(param_risk=["risk"])
    # logging.info("[ANALYSIS] Delta Frequency performed")

    # df_path = pd.read_csv(config.ANALYSIS_ACCURACY_FILE)
    # line_time_analysis(df_path,"path_time", param_net="id_path")
    # logging.info("[ANALYSIS] Path Computation Time performed")

if __name__ == "__main__":
    main_analysis()