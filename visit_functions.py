import recursive_functions
import auxiliar_functions

def visitAssign(node, source, tainted_variables, initialized_variables, potential_tainted_var, sanitizers_by_vuln, sanitizers, sinks):
    for node_target in node["targets"]:
        if node_target["ast_type"] == "Name":
            if node_target["id"] not in initialized_variables:
                initialized_variables.append(node_target["id"])
            
            potential_tainted_var = node_target["id"]

            if "args" in node["value"] and node["value"]["args"] != []:
                if node["value"]["ast_type"] == "Call":
                    # assumption: sanitizer is always a function
                    old_len = len(tainted_variables)
                    
                    tainted_variables, before_is_sanitizer = recursive_functions.argsVisitor(node["value"]["args"], source, tainted_variables,
                                                                        initialized_variables, node["value"], potential_tainted_var, sanitizers_by_vuln, sanitizers, sinks, "")
                    
                    if old_len != len(tainted_variables) and tainted_variables[-1].split("=")[0] != "n_source":
                        auxiliar_functions.insertTaintedVar(tainted_variables, potential_tainted_var, source)
                    
                    if node["value"]["func"]["id"] == source or node["value"]["func"]["id"] in tainted_variables:
                        auxiliar_functions.insertTaintedVar(tainted_variables, potential_tainted_var, source)
                    
                    # sink = sanitizer(...) --> unsanitized_flow is always no (... -> needs to have at least one tainted variable)
                    if node["value"]["func"]["id"] in sanitizers and potential_tainted_var in sinks:
                        keys = [(''+source, ''+potential_tainted_var)]
                        for key in keys:
                            if key in sanitizers_by_vuln:
                                for el in sanitizers_by_vuln[key][0]:
                                    if len(el) == 1 and el[0] == potential_tainted_var:
                                        if list(node["value"]["func"]["id"]) not in sanitizers_by_vuln[key][0]:
                                            sanitizers_by_vuln[key][0].append(
                                                list(node["value"]["func"]["id"]))
                                            sanitizers_by_vuln[key][1] = "no"
                            # elements inserted by order
                            # last element is sanitizer --> sink is sanitized without unsanitized flows
                            if key in sanitizers_by_vuln and len(sanitizers_by_vuln[key]) >= 1:
                                if sanitizers_by_vuln[key][0][-1][0] in sanitizers:
                                    sanitizers_by_vuln[key][1] = "no"
                    return tainted_variables
            else:
                if node["value"]["ast_type"] == "Constant":
                    pass
                
                elif node["value"]["ast_type"] == "Call":
                    if source == node["value"]["func"]["id"] or node["value"]["func"]["id"] in tainted_variables:
                        return auxiliar_functions.insertTaintedVar(tainted_variables, potential_tainted_var, source)
                
                elif node["value"]["ast_type"] == "Name":
                    tainted_variables = auxiliar_functions.checkNewSource(
                        node["value"]["id"], source, initialized_variables, tainted_variables)
                    
                    #ex: e = f(c) and c was sanitized -- so e was sanitized too
                    possible_sanitized = node["value"]["id"]
                    if (''+source, ''+possible_sanitized) in sanitizers_by_vuln:
                        keys = [(''+source, ''+potential_tainted_var)]
                        for key in keys:
                            for x in sanitizers_by_vuln[(''+source, ''+possible_sanitized)]:
                                if type(x) != str:
                                    for santz in x:
                                        if key not in sanitizers_by_vuln:
                                            sanitizers_by_vuln[key] = [[list(santz)], sanitizers_by_vuln[(''+source, ''+possible_sanitized)][1]]
                                        else:
                                            if list(santz) not in sanitizers_by_vuln[(''+source, ''+possible_sanitized)][0]:
                                                sanitizers_by_vuln[key][0].append(list(santz))
                                                if sanitizers_by_vuln[(''+source, ''+possible_sanitized)][1] != "no":
                                                    sanitizers_by_vuln[key][1] = sanitizers_by_vuln[(''+source, ''+possible_sanitized)][1]

                    if source == node["value"]["id"] or node["value"]["id"] in tainted_variables:
                        return auxiliar_functions.insertTaintedVar(tainted_variables, potential_tainted_var, source)

                elif node["value"]["ast_type"] == "BinOp":
                    tainted_variables = recursive_functions.binOpVisitor(
                        node["value"], source, tainted_variables, initialized_variables, "", potential_tainted_var, sanitizers_by_vuln, sanitizers, sinks, "")
                
                return tainted_variables


def visitExp(node, source, tainted_variables, initialized_variables, potential_tainted_var, sanitizers_by_vuln, sanitizers, sinks):
    for el in node["value"]["args"]:
        if node["value"]["ast_type"] == "Call":
            recursive_functions.argsVisitor(
                node["value"]["args"], source, tainted_variables, initialized_variables, node["value"], "", sanitizers_by_vuln, sanitizers, sinks, node["value"]["func"]["id"])
    return tainted_variables


def visitSubNode(node, source, tainted_variables, initialized_variables, sanitizers_by_vuln, sanitizers, sinks, implicit):
    for subnode in node:
        potential_tainted_var = 0
        if subnode == "ast_type":
            if node[subnode] == "Assign":
                visitAssign(node, source, tainted_variables,
                            initialized_variables, potential_tainted_var, sanitizers_by_vuln, sanitizers, sinks)
            if node[subnode] == "Expr":
                visitExp(node, source, tainted_variables,
                         initialized_variables, potential_tainted_var, sanitizers_by_vuln, sanitizers, sinks)
        return tainted_variables

def testComparator(el, source, initialized_variables, tainted_variables, condition_variables):
    '''
    Auxiliar function of visitImplicitCond().
    '''
    
    if el["ast_type"] == "Name":
        # add to tainted variables as source if not initialized
        auxiliar_functions.checkNewSource(el["id"], source,
                       initialized_variables, tainted_variables)
        condition_variables.append(el["id"])
    elif el["ast_type"] == "Call":
        pass
        # call recursive_functions.argsvisitor
        # condition_variables.append(el["func"]["id"])
    elif el["ast_type"] == "BinOp":
        pass
        # call recursive_functions.binopvisitor
        # condition_variables.append(el["right"][id])
        # condition_variables.append(el["left"][id])


def visitImplicitCond(test, source, initialized_variables, tainted_variables):
    '''
    This function evaluates the compare arguments of If's and While's.
    '''
    
    condition_variables = []
    if test["ast_type"] == "Compare":
        if test["comparators"]:
            for el in test["comparators"]:
                testComparator(el, source, initialized_variables,
                               tainted_variables, condition_variables)
        if test["left"]:
            testComparator(test["left"], source, initialized_variables,
                           tainted_variables, condition_variables)
    return condition_variables