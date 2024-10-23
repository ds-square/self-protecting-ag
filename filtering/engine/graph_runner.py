import sympy



class GraphRunner():
    
    ## NORMAL GRAPH OPERATION ##

    def check_if_cve_closed(local_cve,local_cve_to_cpe_tree,discarded_cpe,confirmed_cpe):
        is_cve_closed = True
        is_cve_confirmed = False
        is_cve_discarded = False

        for and_cpe in local_cve_to_cpe_tree[local_cve]:
            if len(and_cpe)==1:
                # One element in the and
                cpe = and_cpe[0]
                if cpe in confirmed_cpe:
                    is_cve_closed = True
                    is_cve_confirmed = True
                    break # One true successfully breaks all
            else:
                # Need to handle multiple elements in the and
                and_true = True
                for cpe in and_cpe:
                    if cpe not in confirmed_cpe:
                        and_true = False
                        break # One false or undecided successfully makes the end not true
                if and_true == True:
                    is_cve_closed = True
                    is_cve_confirmed = True
                    break # One true successfully breaks all
            
            for cpe in and_cpe:
                if (cpe not in discarded_cpe) and (cpe not in confirmed_cpe):
                    # At least one CPE still needs to be validated
                    # Is this CPE part of a bigger and?
                    if len(and_cpe) == 1:
                        # No
                        is_cve_closed = False
                        break 
                    else:
                        # Yes, see if any other element is true
                        can_and_be_true = True
                        for cpe_other in and_cpe:
                            if cpe_other in discarded_cpe:
                                can_and_be_true = False
                                break 
                        if can_and_be_true == True:
                            is_cve_closed = False
                            break

            if (is_cve_closed==True) and (is_cve_confirmed==False):
                # All cpe are either discarded or confirmed
                is_cve_discarded = True

        return is_cve_closed,is_cve_confirmed,is_cve_discarded


    def get_cpe_from_node(node_name,local_cpe_vendor_to_cpe,local_cpe_product_to_cpe,local_cpe_version_to_cpe):
        cpe_set = set()
        if node_name in local_cpe_vendor_to_cpe:
            cpe_set = cpe_set.union(set(local_cpe_vendor_to_cpe[node_name]))
            #for cpe in local_cpe_vendor_to_cpe[node_name]:
                #cpe_set.add(cpe)
        if node_name in local_cpe_product_to_cpe:
            cpe_set = cpe_set.union(set(local_cpe_product_to_cpe[node_name]))
            #for cpe in local_cpe_product_to_cpe[node_name]:
                #cpe_set.add(cpe)
        if node_name in local_cpe_version_to_cpe:
            cpe_set = cpe_set.union(set(local_cpe_version_to_cpe[node_name]))
            #for cpe in local_cpe_version_to_cpe[node_name]:
                #cpe_set.add(cpe)
        return cpe_set


    def remove_subtree_iter(graph,start_node):
        neighborlist = list()
        for neighbor in graph.neighbors(start_node):
            if "_sink" not in neighbor:
                neighborlist.append(neighbor)
        for neighbor in neighborlist:
            if neighbor in graph.nodes:
                GraphRunner.remove_subtree_iter(graph,neighbor)
        graph.remove_node(start_node)


    def validate_node(selected_node,local_inventory,detail_level):
        for elem in local_inventory:
            if detail_level == "version":
                if elem == selected_node:
                    if local_inventory[elem] == "confirmed":
                        return True
            elif detail_level == "product":
                splitelem = elem.split(":")
                newelem = splitelem[0]+":"+splitelem[1]+":"+splitelem[2]
                if newelem == selected_node:
                    if local_inventory[elem] == "confirmed":
                        return True
            else:
                splitelem = elem.split(":")
                newelem = splitelem[0]+":"+splitelem[1]
                if newelem == selected_node:
                    if local_inventory[elem] == "confirmed":
                        return True
        return False



    ## COHERENCE ##

    def coherent_cpe_split(cpe):
        part = cpe[:cpe.find(":")]
        cpe = cpe[cpe.find(":")+1:]
        vendor = cpe[:cpe.find(":")]
        cpe = cpe[cpe.find(":")+1:]
        if ":" in cpe:
            product = cpe[:cpe.find(":")]
            cpe = cpe[cpe.find(":")+1:]
            version = cpe
        else:
            product = cpe
            version = "-"
        return part,vendor,product,version



    ## SYMPY OPERATION ##

    def sympy_to_structure(sympy_dnf_formula):
        return_str = list()
        sympy_dnf_formula_string = str(sympy_dnf_formula)

        if "(" in sympy_dnf_formula_string:
            # AND handle
            for subelem in sympy_dnf_formula_string.split("("):
                if ")" in subelem:
                    # Inside AND
                    and_elem = subelem.split(")")[0]
                    and_struct = list()
                    for elem in and_elem.split("&"):
                        if and_elem.strip() != "":
                            and_struct.append(elem.strip())
                    if and_struct != []:
                        return_str.append(and_struct)
                    
                    subelem = subelem.split(")")[1]
                    for elem in subelem.split("|"):
                        if elem.strip() != "":
                            return_str.append([elem.strip()])
                else:
                    for elem in subelem.split("|"):
                        if elem.strip() != "":
                            return_str.append([elem.strip()])
        elif "&" in sympy_dnf_formula_string:
            # Only AND
            and_elem = list()
            for elem in sympy_dnf_formula_string.split("&"):
                if elem.strip() != "":
                    and_elem.append(elem.strip())
            return_str.append(and_elem)
        else:
            # No AND
            for elem in sympy_dnf_formula_string.split("|"):
                if elem.strip() != "":
                    return_str.append([elem.strip()])

        return return_str



    def assemble_logic_tree(original_cve_cpe_tree_structure):
        cve_tree_vendor = False
        cve_tree_product = False
        cve_tree_version = False
        cpe_to_symbol = dict()
        symbol_to_cpe = dict()
        for and_cpe in original_cve_cpe_tree_structure:
            and_element_vendor = True
            and_element_product = True
            and_element_version = True
            for cpe in and_cpe:
                part,vendor,product,version = GraphRunner.coherent_cpe_split(cpe)

                if part+":"+vendor not in cpe_to_symbol:
                    cpe_to_symbol[part+":"+vendor] = sympy.Symbol(part+":"+vendor)
                    symbol_to_cpe[cpe_to_symbol[part+":"+vendor]] = part+":"+vendor
                if part+":"+vendor+":"+product not in cpe_to_symbol:
                    cpe_to_symbol[part+":"+vendor+":"+product] = sympy.Symbol(part+":"+vendor+":"+product)
                    symbol_to_cpe[cpe_to_symbol[part+":"+vendor+":"+product]] = part+":"+vendor+":"+product
                if part+":"+vendor+":"+product+":"+version not in cpe_to_symbol:
                    cpe_to_symbol[part+":"+vendor+":"+product+":"+version] = sympy.Symbol(part+":"+vendor+":"+product+":"+version)
                    symbol_to_cpe[cpe_to_symbol[part+":"+vendor+":"+product+":"+version]] = part+":"+vendor+":"+product+":"+version

                and_element_vendor = sympy.And(and_element_vendor,cpe_to_symbol[part+":"+vendor])
                and_element_product = sympy.And(and_element_product,cpe_to_symbol[part+":"+vendor+":"+product])
                and_element_version = sympy.And(and_element_version,cpe_to_symbol[part+":"+vendor+":"+product+":"+version])
            # And is now populated
            cve_tree_vendor = sympy.Or(cve_tree_vendor,and_element_vendor)
            cve_tree_product = sympy.Or(cve_tree_product,and_element_product)
            cve_tree_version = sympy.Or(cve_tree_version,and_element_version)
        # tree is now populated
        cve_tree_vendor = sympy.to_dnf(sympy.simplify_logic(cve_tree_vendor))
        cve_tree_product = sympy.to_dnf(sympy.simplify_logic(cve_tree_product))
        cve_tree_version = sympy.to_dnf(sympy.simplify_logic(cve_tree_version))

        return cve_tree_vendor,cve_tree_product,cve_tree_version



    ## TREE OPERATION ##

    def evaluate_cpe_tree(local_cve_to_cpe_tree,confirmed_cpe,discarded_cpe):
        
        new_cve_to_cpe_tree = dict()

        for cve in local_cve_to_cpe_tree:
            new_cve_to_cpe_tree[cve] = set()
            for and_cpe in local_cve_to_cpe_tree[cve]:
                new_and_cpe = list()
                is_and_valid = True
                for cpe in and_cpe:
                    if cpe in confirmed_cpe:
                        # cpe is confirmed, don't move
                        pass
                    elif cpe in discarded_cpe:
                        # cpe is negated, throw away the and
                        is_and_valid = False
                        break
                    else:
                        new_and_cpe.append(cpe)
                
                if (is_and_valid == True) and (new_and_cpe != list()):
                    # and is valid AND and is filled
                    new_cve_to_cpe_tree[cve].add(frozenset(new_and_cpe))

            # cast to list
            new_cve_to_cpe_tree[cve] = list(new_cve_to_cpe_tree[cve])


        cleaned_cve_to_cpe_tree = dict()
        for cve in new_cve_to_cpe_tree:
            if ((len(new_cve_to_cpe_tree[cve])>1) or ((len(new_cve_to_cpe_tree[cve]) == 1) and (len(new_cve_to_cpe_tree[cve][0]) > 0))):
                cleaned_cve_to_cpe_tree[cve] = list()
                for elem in new_cve_to_cpe_tree[cve]:
                    cleaned_cve_to_cpe_tree[cve].append(list(elem))


        return cleaned_cve_to_cpe_tree



    def rebuild_truncated_cpe_trees_old(local_cve_to_cpe_tree):
        local_cve_to_cpe_tree_vendor = dict()
        local_cve_to_cpe_tree_product = dict()
        local_cve_to_cpe_tree_version = dict()


        # Assemble tree
        for cve in local_cve_to_cpe_tree:
            print("F1")
            cve_tree_vendor,cve_tree_product,cve_tree_version = GraphRunner.assemble_logic_tree(local_cve_to_cpe_tree[cve])

            print("F2")
            cve_tree_vendor_struct = GraphRunner.sympy_to_structure(cve_tree_vendor)
            print("F3")
            cve_tree_product_struct = GraphRunner.sympy_to_structure(cve_tree_product)
            print("F4")
            cve_tree_version_struct = GraphRunner.sympy_to_structure(cve_tree_version)
            print("F5")

            local_cve_to_cpe_tree_vendor[cve] = cve_tree_vendor_struct
            local_cve_to_cpe_tree_product[cve] = cve_tree_product_struct
            local_cve_to_cpe_tree_version[cve] = cve_tree_version_struct


        return local_cve_to_cpe_tree_vendor, local_cve_to_cpe_tree_product, local_cve_to_cpe_tree_version



    def rebuild_truncated_cpe_trees(local_cve_to_cpe_tree):
        local_cve_to_cpe_tree_vendor = dict()
        local_cve_to_cpe_tree_product = dict()
        local_cve_to_cpe_tree_version = dict()


        # Assemble tree
        for cve in local_cve_to_cpe_tree:
            local_cve_to_cpe_tree_vendor[cve] = set()
            local_cve_to_cpe_tree_product[cve] = set()
            local_cve_to_cpe_tree_version[cve] = set()

            for and_cpe in local_cve_to_cpe_tree[cve]:
                and_cpe_vendor = set()
                and_cpe_product = set()
                and_cpe_version = set()

                for cpe in and_cpe:
                    part,vendor,product,version = GraphRunner.coherent_cpe_split(cpe)
                    and_cpe_vendor.add(part+":"+vendor)
                    and_cpe_product.add(part+":"+vendor+":"+product)
                    and_cpe_version.add(part+":"+vendor+":"+product+":"+version)

                local_cve_to_cpe_tree_vendor[cve].add(frozenset(and_cpe_vendor))
                local_cve_to_cpe_tree_product[cve].add(frozenset(and_cpe_product))
                local_cve_to_cpe_tree_version[cve].add(frozenset(and_cpe_version))

        """
        out_cve_to_cpe_tree_vendor = dict()
        out_cve_to_cpe_tree_product = dict()
        out_cve_to_cpe_tree_version = dict()
        for cve in local_cve_to_cpe_tree_vendor:
            out_cve_to_cpe_tree_vendor[cve] = list()
            out_cve_to_cpe_tree_product[cve] = list()
            out_cve_to_cpe_tree_version[cve] = list()
        """

        return local_cve_to_cpe_tree_vendor, local_cve_to_cpe_tree_product, local_cve_to_cpe_tree_version



    ## USELESS ITEM PRUNING FROM GRAPH ##

    def prune_useless_items(local_graph,local_cve_to_cpe_tree,local_cpe_to_cpe_mod
                            ,local_cve_to_cpe_tree_vendor,local_cve_to_cpe_tree_product,local_cve_to_cpe_tree_version,
                            confirmed_cpe,discarded_cpe,open_cve):
        # Determine which cve is useless or useful
        useless_cve = set()
        useful_cve = set()

        confirmed_cve = set()
        discarded_cve = set()

        for cve in open_cve:
            is_closed = False
            is_closed,is_cve_confirmed,is_cve_discarded = GraphRunner.check_if_cve_closed(cve,local_cve_to_cpe_tree,discarded_cpe,confirmed_cpe)
            if is_closed == True:
                useless_cve.add(cve)
                if is_cve_confirmed == True:
                    confirmed_cve.add(cve)
                elif is_cve_discarded == True:
                    discarded_cve.add(cve)
            else:
                useful_cve.add(cve)

        # Remove useless cpe from graph, if any
        for cve in useless_cve:
            for and_cpe in local_cve_to_cpe_tree[cve]:
                for cpe in and_cpe:
                    for cpe_mod in local_cpe_to_cpe_mod[cpe]:

                        # Check if cpe is used anywhere else
                        cpe_mod_useful = False
                        for cve_useful in useful_cve:
                            for and_cpe_useful in local_cve_to_cpe_tree_vendor[cve_useful]:
                                if cpe_mod in and_cpe_useful:
                                    cpe_mod_useful = True
                                    break
                            for and_cpe_useful in local_cve_to_cpe_tree_product[cve_useful]:
                                if cpe_mod in and_cpe_useful:
                                    cpe_mod_useful = True
                                    break
                            for and_cpe_useful in local_cve_to_cpe_tree_version[cve_useful]:
                                if cpe_mod in and_cpe_useful:
                                    cpe_mod_useful = True
                                    break

                            if cpe_mod_useful == True:
                                break

                        if cpe_mod_useful == False:
                            if cpe_mod in local_graph.nodes:
                                local_graph.remove_node(cpe_mod)

        return confirmed_cve,discarded_cve


    def validate_node_explicit(selected_node,local_inventory,detail_level):
        local_confirmed = set()
        local_discarded = set()
        return_value = False

        for elem in local_inventory:
            if detail_level == "version":
                if elem == selected_node:
                    if local_inventory[elem] == "confirmed":
                        #local_confirmed.add(elem)
                        return_value = True
                        break
                    #elif local_inventory[elem] == "discarded":
                        #local_discarded.add(elem)
            elif detail_level == "product":
                splitelem = elem.split(":")
                newelem = splitelem[0]+":"+splitelem[1]+":"+splitelem[2]
                if newelem == selected_node:
                    if local_inventory[elem] == "confirmed":
                        #local_confirmed.add(elem)
                        return_value = True
                        break
                    #elif local_inventory[elem] == "discarded":
                        #local_discarded.add(elem)
            else:
                splitelem = elem.split(":")
                newelem = splitelem[0]+":"+splitelem[1]
                if newelem == selected_node:
                    if local_inventory[elem] == "confirmed":
                        #local_confirmed.add(elem)
                        return_value = True
                        break
                    #elif local_inventory[elem] == "discarded":
                        #local_discarded.add(elem)
        
        return return_value,local_confirmed,local_discarded
