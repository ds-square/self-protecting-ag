import os, json, sys, os, csv, statistics, random, time, logging
import pandas as pd
import numpy as np
import networkx as nx
import seaborn as sns
import matplotlib.pyplot as plt
from itertools import chain
pd.options.mode.chained_assignment = None

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import config

MARKERS = {0:"o", 1:"+", 2:"s", 3:"x"}
COLORS = {0:"#984ea3", 1:"#4daf4a", 2:"#377eb8", 3:"#e41a1c"}

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

    imp_risk = impact_scores[len(impact_scores)-1]if len(impact_scores)>0 else 0
    lik_risk = statistics.mean(exploit_scores) if len(exploit_scores)>0 else 0

    return {
        "impact": 
        max(impact_scores) if len(impact_scores)>0 else 0,
        # statistics.median(impact_scores) if len(impact_scores)>0 else 0, 
        # statistics.mean(impact_scores) if len(impact_scores)>0 else 0,
        "exploit": 
        max(exploit_scores) if len(exploit_scores)>0 else 0,
        # statistics.median(exploit_scores) if len(exploit_scores)>0 else 0,
        # statistics.mean(exploit_scores) if len(exploit_scores)>0 else 0,
        "score" : 
        max(base_scores) if len(base_scores)>0 else 0,
        # statistics.median(base_scores) if len(base_scores)>0 else 0,
        # statistics.mean(base_scores) if len(base_scores)>0 else 0,
        "risk":
        (imp_risk)*(lik_risk),
        "mod":
        np.linalg.norm(np.array([imp_risk,lik_risk]))
    }, {
        "impact": impact_scores,
        "exploit": exploit_scores,
        "score" : base_scores,
    }

def accuracy_complexity(graph_filenames, a3_filename, reset_accuracy=False):
    if not os.path.exists(config.ANALYSIS_ACCURACY_FILE) or reset_accuracy:
        with open(config.ANALYSIS_ACCURACY_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['network','seed','hosts','vulns','model','filter','aggregation',
                            'num_paths',"id_path","impact","exploit","score",
                            "risk","mod","path_time","source","target"
                            ])

    G_base = nx.read_graphml(a3_filename)
    # all_paths_distances = {x[0]:x[1] for x in nx.all_pairs_shortest_path_length(G_base)}
    # entry_points = {}
    # for src in all_paths_distances.keys():
    #     dict_dist = all_paths_distances[src]
    #     max_val = max(dict_dist.values())
    #     dst = [k for k,v in dict_dist.items() if v >= max_val]
    #     for target in dst:
    #         entry_points[(src,target)]=max_val
    # entry_points = dict(sorted(entry_points.items(), key=lambda x:x[1], reverse=True))

    # sources = []
    # goals = []
    # for entry in entry_points.keys():
    #     if "@" in entry[0] and "@" in entry[1]:
    #         sources.append(entry[0])
    #         goals.append(entry[1])

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
    sources = list(random.sample(entries, config.num_src_risk))
    goals = list(random.sample(entries, config.num_dst_risk))
    
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

        network_params = network_type.split("_")
        n_seed = int(network_params[0].replace("s",""))
        n_host = int(network_params[1].replace("h",""))
        n_vuln = int(network_params[2].replace("v",""))

        aggregation_level = 0
        if "a0" in g_file: aggregation_level=0
        elif "a1" in g_file: aggregation_level=1
        elif "a2" in g_file: aggregation_level=2
        else: aggregation_level=3

        filter_level = 0
        if "f0" in g_file: filter_level=0
        elif "f1" in g_file: filter_level=1
        elif "f2" in g_file: filter_level=2
        else: filter_level=3

        all_risks=[]
        id_count=1
        for s in sources:
            for t in goals:
                if s not in G.nodes() or t not in G.nodes():
                    print("wrong format: ", g_file)
                    continue
                if not nx.has_path(G,s,t): 
                    if s in sources: sources.remove(s)
                    if t in goals: goals.remove(t)
                    print("no path")
                    continue
                else:
                    start = time.perf_counter()

                    current_paths = list(nx.all_simple_paths(G, source=s, target=t))
                    vulns_path=[]
                    for single_path in current_paths:
                        for node_p in single_path:
                            if node_types[node_p] == "vulnerability":
                                vulns_path.append(node_p)

                    if len(vulns_path)<=0: continue
                    risk_values, risk_list_values = compute_risk_analysis(vulns_path, inventory_vulns)
                    risk_values["id"] = id_count
                    
                    end = time.perf_counter()
                    risk_values["time"]=round(end-start,2)
                    risk_values["source"]=s
                    risk_values["target"]=t
                    
                    all_risks.append(risk_values)

                    risk_list_values["hosts"]=n_host
                    risk_list_values["vulns"]=n_vuln
                    risk_list_values["model"]=model
                    risk_list_values["filter"]=filter_level
                    risk_list_values["aggregation"]=aggregation_level
                    risk_list_values["id_path"]=id_count
                    all_risk_lists.append(risk_list_values)
                    
                    id_count+=1

        with open(config.ANALYSIS_ACCURACY_FILE, 'a', newline='') as fd:
            writer = csv.writer(fd)
            for risk_v in all_risks:
                writer.writerow([
                    network_type,n_seed,n_host,n_vuln,model,filter_level,aggregation_level,
                    len(all_risks),risk_v["id"],risk_v["impact"],risk_v["exploit"],
                    risk_v["score"], risk_v["risk"], risk_v["mod"],
                    risk_v["time"], risk_v["source"], risk_v["target"]
                ])

    return pd.DataFrame(all_risk_lists)

def write_space_complexity(reset_space=False):
    if not os.path.exists(config.ANALYSIS_SPACE_FILE) or reset_space:
        with open(config.ANALYSIS_SPACE_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['network','seed','hosts','vulns','model','filter','aggregation',
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

            filter_level = 0
            if "f0" in graph_file: filter_level=0
            elif "f1" in graph_file: filter_level=1
            elif "f2" in graph_file: filter_level=2
            else: filter_level=3

            setting_net = graph_file.replace(".graphml","").split("_")
            model = setting_net[0]
            network_params = network_context.split("_")
            n_seed = int(network_params[0].replace("s",""))
            n_host = int(network_params[1].replace("h",""))
            n_vuln = int(network_params[2].replace("v",""))

            with open(config.ANALYSIS_SPACE_FILE, 'a', newline='') as fd:
                writer = csv.writer(fd)
                writer.writerow([
                    network_context,n_seed,n_host,n_vuln,model,filter_level,aggregation_level,
                    num_nodes,num_edges,density,num_components,
                    list(np.quantile(in_degrees_values,[0.25,0.5,0.75])) if len(in_degrees_values)>0 else None,
                    list(np.quantile(out_degrees_values,[0.25,0.5,0.75])) if len(out_degrees_values)>0 else None,
                    list(np.quantile(closeness_centr_values,[0.25,0.5,0.75])) if len(closeness_centr_values)>0 else None,
                    sum(in_degrees_values)/len(in_degrees_values) if len(in_degrees_values)>0 else None,
                    sum(out_degrees_values)/len(out_degrees_values) if len(out_degrees_values)>0 else None,
                    sum(closeness_centr_values)/len(closeness_centr_values) if len(closeness_centr_values)>0 else None,
                ])

def space_analysis(params_space=["num_edges"],param_net="hosts",stats_file=config.ANALYSIS_SPACE_FILE):
    # plt.rcParams.update({'font.size': 22})
    df = pd.read_csv(stats_file)
    df=df[df["vulns"]==20]

    grouped_by_model = df.groupby(by=["model"])
    for model_id, df_model in grouped_by_model:
        fig, axs = plt.subplots(ncols=1, nrows=len(params_space), squeeze=False, layout="constrained")
        fig.set_figwidth(9)
        fig.set_figheight(7)
        
        for i in range(0,len(params_space)):
            curr_param = params_space[i]
            grouped_by_net = df_model.groupby(by=["hosts","vulns"])
            x_vals=[]
            y_vals={}
            for params_net, df_paramnet in grouped_by_net:
                grouped_by_aggragation = df_paramnet.groupby(by=["aggregation"])
                x_vals.append(list(df_paramnet[param_net])[0])
                for aggr_level, df_aggrlevel in grouped_by_aggragation:
                    if aggr_level not in y_vals.keys(): y_vals[aggr_level] = [statistics.median(list(df_aggrlevel[curr_param]))]
                    else: y_vals[aggr_level].append(statistics.median(list(df_aggrlevel[curr_param])))
                    
            for aggregation_level in y_vals.keys():
                axs[i,0].plot(x_vals, y_vals[aggregation_level], label=str(aggregation_level), 
                              linewidth='1', marker=MARKERS[aggregation_level], color=COLORS[aggregation_level])
            
            axs[i,0].set_xlabel(param_net)
            axs[i,0].set_xticks(x_vals)
            axs[i,0].set_ylabel(curr_param)
            axs[i,0].legend(title="Agg. levels", ncol=2)
        
        fig.suptitle(model_id)
        plt.savefig(config.PLOT_SPACE_FOLDER+model_id+"_"+param_net+".png")#, bbox_inches='tight')
        plt.close()

def line_time_analysis(df,params_time,param_net="hosts"):
    # plt.rcParams.update({'font.size': 22})
    df=df[df["vulns"]==20]

    grouped_by_model = df.groupby(by=["model"])
    for model_id, df_model in grouped_by_model:
        fig, ax = plt.subplots(1, 1, layout="constrained")
        fig.set_figwidth(9)
        fig.set_figheight(3)
        
        grouped_by_net = df_model.groupby(by=["hosts","vulns"])
        x_vals=[]
        y_vals={}
        for params_net, df_paramnet in grouped_by_net:
            grouped_by_aggragation = df_paramnet.groupby(by=["aggregation"])
            x_vals.append(list(df_paramnet[param_net])[0])
            for aggr_level, df_aggrlevel in grouped_by_aggragation:
                if params_time == "path_time":
                    if aggr_level not in y_vals.keys(): y_vals[aggr_level] = [sum(list(df_aggrlevel[params_time]))]
                    else: y_vals[aggr_level].append(sum(list(df_aggrlevel[params_time])))
                else:
                    if aggr_level not in y_vals.keys(): y_vals[aggr_level] = [statistics.median(list(df_aggrlevel[params_time]))]
                    else: y_vals[aggr_level].append(statistics.median(list(df_aggrlevel[params_time])))
                
        for aggregation_level in y_vals.keys():
            if aggregation_level==0 and params_time=="aggregation_time": continue
            ax.plot(x_vals, y_vals[aggregation_level], label=str(aggregation_level), 
                    linewidth='1', marker=MARKERS[aggregation_level], color=COLORS[aggregation_level])
        
        ax.set_xlabel(param_net)
        ax.set_xticks(x_vals)
        ax.set_ylabel(params_time)
        ax.legend(title="Agg. levels", ncol=2)
        
        if params_time == "aggregation_time": 
            plt.savefig(config.PLOT_TIME_FOLDER+params_time+"_"+param_net+".png")#, bbox_inches='tight')
            plt.close()
            break
        else:
            fig.suptitle(model_id)
            plt.savefig(config.PLOT_TIME_FOLDER+params_time+"_"+model_id+"_"+param_net+".png")#, bbox_inches='tight')
            plt.close()

def confusion_matrix_accuracy():
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
                if model_name+"_f0" in graph_file:
                    filenames_model.append(config.GRAPH_FOLDER+network_context+"/"+graph_file)
                if model_name+"_f0-a0" in graph_file: reference_file_model = config.GRAPH_FOLDER+network_context+"/"+graph_file

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

def distribution_risk_analysis(param_risk=["score","impact","exploit"], param_net="hosts"):
    
    labels_legend = list(COLORS.keys())
    legend_lines = [plt.Line2D([0], [0], color=COLORS[0], lw=2),
                    plt.Line2D([0], [0], color=COLORS[1], lw=2),
                    plt.Line2D([0], [0], color=COLORS[2], lw=2),
                    plt.Line2D([0], [0], color=COLORS[3], lw=2)]
        
    for model_name in ["NETSPA"]:#,"NETSPA", "TVA","MULTI"]:
        fig, axs = plt.subplots(3, 1)
        fig.set_figwidth(15)
        fig.set_figheight(7)

        list_dfs=[]
        for network_context in os.listdir(config.GRAPH_FOLDER):
            if "h100" in network_context or "h50" in network_context: continue
            if "s1" not in network_context: continue
            
            filenames_model=[]
            reference_file_model=""
            for graph_file in os.listdir(config.GRAPH_FOLDER+network_context):
                if model_name not in graph_file: continue

                if model_name+"_f0" in graph_file:
                    filenames_model.append({config.GRAPH_FOLDER+network_context+"/"+graph_file:config.NETWORK_FOLDER+network_context+"/"+graph_file.split("_")[1].replace("graphml","json")})
                if model_name+"_f0-a0" in graph_file: reference_file_model = config.GRAPH_FOLDER+network_context+"/"+graph_file

            df_risk_model = accuracy_complexity(filenames_model, reference_file_model, True if len(list_dfs)==0 else False)
            list_dfs.append(df_risk_model)
            print("Computed paths in ", network_context)
        
        df_all_distro = pd.concat(list_dfs)

        grouped_by_network = df_all_distro.groupby(by=["hosts","vulns"])
        x_hosts=[]
        count=0
        for net_params, df_net in grouped_by_network:
            count+=1
            num_hosts = net_params[0]
            x_hosts.append(num_hosts)

            width = 1
            x=int(num_hosts)
            offset = width# * multiplier
            
            grouped_by_aggragation = df_net.groupby(by=["aggregation"])
            valuesByAggregation = {}
            for i in range(0,len(param_risk)):
                risk_name=param_risk[i]
                for aggregation_level, df_aggregation in grouped_by_aggragation:
                    if aggregation_level not in valuesByAggregation.keys(): valuesByAggregation[aggregation_level] = {}
                    if risk_name not in valuesByAggregation[aggregation_level].keys(): valuesByAggregation[aggregation_level][risk_name] = []
                    
                    valuesByAggregation[aggregation_level][risk_name] += list(df_aggregation[risk_name])

                if 0 in valuesByAggregation.keys():
                    axs[i].boxplot(list(chain(*valuesByAggregation[0][risk_name])), positions=[x+(-1)*offset],widths=width,patch_artist=True,boxprops=dict(facecolor=COLORS[0]),medianprops=dict(color="#000000"))
                if 1 in valuesByAggregation.keys():
                    axs[i].boxplot(list(chain(*valuesByAggregation[1][risk_name])), positions=[x+(0)*offset],widths=width,patch_artist=True,boxprops=dict(facecolor=COLORS[1]),medianprops=dict(color="#000000"))
                if 2 in valuesByAggregation.keys():
                    axs[i].boxplot(list(chain(*valuesByAggregation[2][risk_name])), positions=[x+(1)*offset],widths=width,patch_artist=True,boxprops=dict(facecolor=COLORS[2]),medianprops=dict(color="#000000"))
                if 3 in valuesByAggregation.keys():
                    axs[i].boxplot(list(chain(*valuesByAggregation[3][risk_name])), positions=[x+(2)*offset],widths=width,patch_artist=True,boxprops=dict(facecolor=COLORS[3]),medianprops=dict(color="#000000"))
                
                axs[i].set_ylabel(risk_name)
            
        for i in range(0,len(param_risk)):
            axs[i].set_xticks(x_hosts)
            axs[i].set_xticklabels(x_hosts)
            if i == 0:
                axs[i].legend(legend_lines, labels_legend, title="Aggr. level")
            if i == len(param_risk)-1:
                axs[i].set_xlabel(param_net)
                    
        # fig.suptitle(net_id.replace("_filter_aggregation","") + " - " + model_id)
        plt.savefig(config.PLOT_ACCURACY_FOLDER+"distro"+model_name+".png", bbox_inches='tight')
        plt.close()

def frequency_delta_analysis(param_risk=["score","impact","exploit"], stats_file=config.ANALYSIS_ACCURACY_FILE):
    
    is_first=False
    for model_name in ["NETSPA"]:
        for network_context in os.listdir(config.GRAPH_FOLDER):
            # if "h100" in network_context or "h50" in network_context: continue
            if "s"+str(config.diversity[0]) not in network_context: continue
            
            filenames_model=[]
            reference_file_model=""
            for graph_file in os.listdir(config.GRAPH_FOLDER+network_context):
                if model_name not in graph_file: continue

                if model_name+"_f0" in graph_file:
                    filenames_model.append({config.GRAPH_FOLDER+network_context+"/"+graph_file:config.NETWORK_FOLDER+network_context+"/"+graph_file.split("_")[1].replace("graphml","json")})
                if model_name+"_f0-a3" in graph_file: reference_file_model = config.GRAPH_FOLDER+network_context+"/"+graph_file

            accuracy_complexity(filenames_model, reference_file_model, not is_first)
            if not is_first: is_first=True
            print("Computed paths in ", network_context)
    
    df = pd.read_csv(stats_file)
    df=df[df["vulns"]==20]

    grouped_by_model = df.groupby(by=["model"])
    for model_id, df_model in grouped_by_model:
        
        fig, axs = plt.subplots(len(param_risk),1)
        fig.set_figwidth(10)
        fig.set_figheight(10)
        
        x_vals = []
        for i in range(0,len(param_risk)):
            risk_name = param_risk[i]
            dict_diff_count = {}
            grouped_by_net = df_model.groupby(by=["seed","hosts","vulns","source","target","id_path"])
            for params_net, df_paramnet in grouped_by_net:
                df_aggr_0 = df_paramnet[df_paramnet["aggregation"] == 0]
                if len(df_aggr_0[risk_name]) > 0: val0 = list(df_aggr_0[risk_name])[0]
                else: continue

                grouped_by_aggregation = df_paramnet.groupby(by=["aggregation"])
                for aggr_level, df_aggr in grouped_by_aggregation:
                    if aggr_level == 0: continue
                    val_ = list(df_aggr[risk_name])[0]
                    diff = round(abs(val_-val0),0)
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

            indexes_remove = []
            for k_aggr in dict_bars.keys():
                list_freq = dict_bars[k_aggr]
                for j in range(0,len(list_freq)):
                    if list_freq[j] == 0: indexes_remove.append(j)
            
            indexes_remove_set = list(set(indexes_remove))
            indexes_remove_set.sort(reverse=True)
            
            for j in indexes_remove_set:
                if indexes_remove.count(j) >= 3:
                    for k_aggr in dict_bars.keys():
                        list_freq = dict_bars[k_aggr]
                        list_freq.pop(j)
                        dict_bars[k_aggr] = list_freq
                    x_vals.pop(j)
            
            x = np.array(x_vals)
            width = 0.25
            multiplier = 0

            for attribute, measurement in dict_bars.items():
                offset = width * multiplier
                rects = axs[i].bar(x + offset, measurement, width, label=attribute, 
                            color=COLORS[attribute], edgecolor='black')
                axs[i].bar_label(rects, padding=3)
                multiplier += 1

            axs[i].set_ylabel('num. occurrences')
            axs[i].set_xlabel('delta '+risk_name)
            # axs[i].set_xlim(-0.5,12)
            
            xtick_10 = np.arange(12)
            axs[i].set_xticks(xtick_10+width, xtick_10)
            # axs[i].set_xticklabels(x_vals, rotation = 90)
            axs[i].legend(title="Agg. levels")

        plt.savefig(config.PLOT_ACCURACY_FOLDER+"frequency"+model_id+".png", bbox_inches='tight')
        plt.close()

def main_analysis():
    
    logging.basicConfig(filename='logging/analysis.log', level=logging.INFO, 
        format='%(asctime)s - %(levelname)s: %(message)s')
    logging.info("[ANALYSIS] START")

    if not os.path.exists(config.ANALYSIS_FOLDER): os.mkdir(config.ANALYSIS_FOLDER)
    if not os.path.exists(config.PLOT_FOLDER): os.mkdir(config.PLOT_FOLDER)
    if not os.path.exists(config.PLOT_SPACE_FOLDER): os.mkdir(config.PLOT_SPACE_FOLDER)
    if not os.path.exists(config.PLOT_TIME_FOLDER): os.mkdir(config.PLOT_TIME_FOLDER)
    if not os.path.exists(config.PLOT_ACCURACY_FOLDER): os.mkdir(config.PLOT_ACCURACY_FOLDER)

    """
    Space Analysis
    """
    write_space_complexity(True)
    space_analysis(["num_edges","num_nodes","density"])#,"num_strong_components","avg_indegree","avg_outdegree","avg_close_centrality"])
    logging.info("[ANALYSIS] Space Complexity performed")

    """
    Time Analysis
    """
    df_gen = pd.read_csv(config.ANALYSIS_TIME_FILE)
    line_time_analysis(df_gen,"generation_time")

    df_agg = pd.read_csv(config.ANALYSIS_AGGREGATION_FILE)
    line_time_analysis(df_agg,"aggregation_time")

    df_gen.rename(columns={"generation_time": "time"}, inplace=True)
    df_agg.rename(columns={"aggregation_time": "time"}, inplace=True)
    df_tot = pd.concat([df_gen, df_agg]).groupby(['network','seed','hosts','vulns','model','filter','aggregation']).sum().reset_index()
    line_time_analysis(df_tot,"time")

    logging.info("[ANALYSIS] Time Complexity performed")

    """
    Accuracy Analysis
    """
    confusion_matrix_accuracy()
    logging.info("[ANALYSIS] Confusion Matrix performed")

    # distribution_risk_analysis() ##TODO: measure time for path computation
    # logging.info("[ANALYSIS] Risk Distribution performed")

    frequency_delta_analysis(param_risk=["risk","mod"])
    logging.info("[ANALYSIS] Delta Frequency performed")

    df_path = pd.read_csv(config.ANALYSIS_ACCURACY_FILE)
    line_time_analysis(df_path,"path_time")
    logging.info("[ANALYSIS] Path Computation Time performed")