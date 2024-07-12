#file with needed code
import auxiliar_functions

def binOpVisitor(element, source, tainted_variables, initialized_variables, node, target, sanitizers_by_vuln, sanitizers, sinks, expr_target):
    if element["ast_type"] == "BinOp":
        binOpVisitor(element["left"], source,
                     tainted_variables, initialized_variables, node, target, sanitizers_by_vuln, sanitizers, sinks, expr_target)

        if element["right"]["ast_type"] == "Name":
            potential_tainted_var = element["right"]["id"]
            tainted_variables = auxiliar_functions.checkNewSource(
                potential_tainted_var, source, initialized_variables, tainted_variables)
            
            evaluateExistingSanitizersBinOp(node, source, potential_tainted_var, tainted_variables, sanitizers, sanitizers_by_vuln, target)
            
            if potential_tainted_var == source or potential_tainted_var in tainted_variables:
                if node != "":
                    auxiliar_functions.insertTaintedVar(tainted_variables, node["func"]["id"], source)
                evaluateSanitizers(node, source, potential_tainted_var, sanitizers, sinks, sanitizers_by_vuln, target, expr_target)

        elif element["right"]["ast_type"] == "Call":
            potential_tainted_var = element["right"]["id"]
            old_len = len(tainted_variables)
            argsVisitor(element["right"]["args"], source, tainted_variables,
                        initialized_variables, element["right"], target, sanitizers_by_vuln, sanitizers, sinks, "")
            if old_len != len(tainted_variables):
                auxiliar_functions.insertTaintedVar(tainted_variables, target, source)

    elif element["ast_type"] == "Name":
        potential_tainted_var = element["id"]
        tainted_variables = auxiliar_functions.checkNewSource(
            potential_tainted_var, source, initialized_variables, tainted_variables)
        
        evaluateExistingSanitizersBinOp(node, source, potential_tainted_var, tainted_variables, sanitizers, sanitizers_by_vuln, target)
        
        if potential_tainted_var == source or potential_tainted_var in tainted_variables:
            auxiliar_functions.insertTaintedVar(tainted_variables, potential_tainted_var, source)
            if node != "" and node["ast_type"] == "Call":
                auxiliar_functions.insertTaintedVar(tainted_variables, node["func"]["id"], source)
            evaluateSanitizers(node, source, potential_tainted_var, sanitizers, sinks, sanitizers_by_vuln, target, expr_target)

    elif element["ast_type"] == "Call":
        potential_tainted_var = element["func"]["id"]
        old_len = len(tainted_variables)
        argsVisitor(element["args"], source, tainted_variables,
                    initialized_variables, element, target, sanitizers_by_vuln, sanitizers, sinks, "")
        if old_len != len(tainted_variables):
            auxiliar_functions.insertTaintedVar(tainted_variables, target, source)

    return tainted_variables


def argsVisitor(element, source, tainted_variables, initialized_variables, parent, target, sanitizers_by_vuln, sanitizers, sinks, expr_target):
    before_is_sanitizer = [None, None]
    for el in element:
        if el["ast_type"] == "Call":
            potential_tainted_var = el["func"]["id"]
            tainted_variables, before_is_sanitizer = argsVisitor(el["args"], source, tainted_variables,
                                                                 initialized_variables, el, target, sanitizers_by_vuln, sanitizers, sinks, expr_target)
            if potential_tainted_var == source or potential_tainted_var in tainted_variables:
                auxiliar_functions.insertTaintedVar(tainted_variables, parent["func"]["id"], source)
                
                #create auxiliar info for beforeIsSanitizer function
                if parent["func"]["id"] in sanitizers:
                    if expr_target != "":
                        before_is_sanitizer[0] = expr_target
                    if target != "":
                        before_is_sanitizer[0] = target  # parent["func"]["id"]
                    before_is_sanitizer[1] = True
            
            evaluateSanitizersCall(parent, source, potential_tainted_var, sanitizers, sanitizers_by_vuln, target, expr_target)

            if len(before_is_sanitizer) == 2 and before_is_sanitizer[1] is True:
                beforeIsSanitizer(before_is_sanitizer, parent, source, potential_tainted_var, sanitizers, sanitizers_by_vuln, target, expr_target)

            evaluateExistingSanitizersArgs(parent, source, potential_tainted_var, sanitizers_by_vuln, target, expr_target)
        
        elif el["ast_type"] == "Name":
            potential_tainted_var = el["id"]
            tainted_variables = auxiliar_functions.checkNewSource(
                potential_tainted_var, source, initialized_variables, tainted_variables)

            if potential_tainted_var == source or potential_tainted_var in tainted_variables:
                auxiliar_functions.insertTaintedVar(tainted_variables, parent["func"]["id"], source)
                evaluateSanitizers(parent, source, potential_tainted_var, sanitizers, sinks, sanitizers_by_vuln, target, expr_target)
            
            evaluateExistingSanitizersArgs(parent, source, potential_tainted_var, sanitizers_by_vuln, target, expr_target)

        elif el["ast_type"] == "BinOp":
            # caso em q la dentro e uma constant mas a funçao e source logo tem de ficar infetado?????????
            tainted_variables = binOpVisitor(
                el, source, tainted_variables, initialized_variables, parent, target, sanitizers_by_vuln, sanitizers, sinks, expr_target)
    return tainted_variables, before_is_sanitizer


def evaluateSanitizers(node, source, potential_tainted_var, sanitizers, sinks, sanitizers_by_vuln, target, expr_target):
    # SE O SANETIZER PERTENCE A LISTA DE SANETIZERS DA VULNERABILIDADE
    if node != "" and node["func"]["id"] in sanitizers:
        if target != "":
            keys = [(''+source, ''+target)]
        if expr_target != "":
            keys = [(''+source, ''+expr_target)]
        for key in keys:
            if key in sanitizers_by_vuln:
                if list(node["func"]["id"]) not in sanitizers_by_vuln[key][0]:
                    sanitizers_by_vuln[key][0].append(
                        list(node["func"]["id"]))
                    sanitizers_by_vuln[key][1] = "yes"
            else:
                sanitizers_by_vuln[key] = [
                    [list(node["func"]["id"])], "yes"]
    if target == "" and node["func"]["id"] in sinks:
        keys = [(''+source, ''+expr_target)]
        for key in keys:
            if (''+source, ''+potential_tainted_var) in sanitizers_by_vuln:
                if key in sanitizers_by_vuln:
                    sanitizers_by_vuln[key][1] = sanitizers_by_vuln[(
                        ''+source, ''+potential_tainted_var)][1]

                for s in sanitizers_by_vuln[(''+source, ''+potential_tainted_var)][0]:
                    if key in sanitizers_by_vuln:
                        if s not in sanitizers_by_vuln[key][0] and s != potential_tainted_var:
                            sanitizers_by_vuln[key][0].append(list(s))
                            sanitizers_by_vuln[key][1] = "yes"
                    else:
                        if s != potential_tainted_var:
                            sanitizers_by_vuln[key] = [[list(s)], "yes"]

def evaluateExistingSanitizersBinOp(node, source, potential_tainted_var, tainted_variables, sanitizers, sanitizers_by_vuln, target):
    # cover case when a BinOp is inside a function
    if (''+source, ''+potential_tainted_var) in sanitizers_by_vuln:
        keys = [(''+source, ''+node["func"]["id"]), (''+source, ''+target)]
        for key in keys:
            for el in sanitizers_by_vuln[(''+source, ''+potential_tainted_var)][0]:
                if el[0] in sanitizers:
                    if key in sanitizers_by_vuln:
                        if list(el[0]) not in sanitizers_by_vuln[(''+source, ''+potential_tainted_var)][0]:
                            sanitizers_by_vuln[key][0].append(list(el[0]))
                            sanitizers_by_vuln[key][1] = "yes"
                    else:
                        sanitizers_by_vuln[key] = [[list(el[0])], "yes"]
    # cover case of BinOp between sanitizer and a name
    if (''+source, ''+target) in sanitizers_by_vuln:
        keys = [(''+source, ''+target)]
        for key in keys:
            if potential_tainted_var == source or potential_tainted_var in tainted_variables:
                sanitizers_by_vuln[key][1] = "yes"

def evaluateExistingSanitizersArgs(parent, source, potential_tainted_var, sanitizers_by_vuln, target, expr_target):
    #ex: e = f(c) and c was sanitized -- so e was sanitized too
    if (''+source, ''+potential_tainted_var) in sanitizers_by_vuln:
        if target != "":
            keys = [(''+source, ''+target), (''+source, ''+parent["func"]["id"])]
        if expr_target != "":
            keys = [(''+source, ''+expr_target), (''+source, ''+parent["func"]["id"])]
        for key in keys:
            for x in sanitizers_by_vuln[(''+source, ''+potential_tainted_var)]:
                if type(x) != str:
                    for santz in x:
                        if key not in sanitizers_by_vuln:
                            sanitizers_by_vuln[key] = [[list(santz)], sanitizers_by_vuln[(''+source, ''+potential_tainted_var)][1]]
                        else:
                            if list(santz) not in sanitizers_by_vuln[(''+source, ''+potential_tainted_var)][0]:
                                sanitizers_by_vuln[key][0].append(list(santz))
                                if sanitizers_by_vuln[(''+source, ''+potential_tainted_var)][1] != "no":
                                    sanitizers_by_vuln[key][1] = sanitizers_by_vuln[(''+source, ''+potential_tainted_var)][1]

def evaluateSanitizersCall(parent, source, potential_tainted_var, sanitizers, sanitizers_by_vuln, target, expr_target):
    if potential_tainted_var in sanitizers and parent["func"]["id"] in sanitizers:
        if target != "":
            keys = [(''+source, ''+target)]
        if expr_target != "":
            keys = [(''+source, ''+expr_target)]
        for key in keys:
            if key in sanitizers_by_vuln:
                if list(parent["func"]["id"]) not in sanitizers_by_vuln[key][0]:
                    sanitizers_by_vuln[key][0].append(
                        [parent["func"]["id"], potential_tainted_var])
                    sanitizers_by_vuln[key][1] = "no"
            else:
                sanitizers_by_vuln[key] = [
                    [[parent["func"]["id"], potential_tainted_var]], "no"]

def beforeIsSanitizer(before_is_sanitizer, parent, source, potential_tainted_var, sanitizers, sanitizers_by_vuln, target, expr_target):
    keys = [(''+source, ''+before_is_sanitizer[0])]
    if expr_target != "":
        new_key = (''+source, ''+before_is_sanitizer[0])
    else:
        new_key = (''+source, ''+potential_tainted_var)
    for key in keys:
        if key in sanitizers_by_vuln and key != new_key:
            for s in sanitizers_by_vuln[key][0]:
                entrei = 1
                if s[0] in sanitizers:
                    if new_key in sanitizers_by_vuln:
                        if list(s[0]) not in sanitizers_by_vuln[new_key][0]:
                            sanitizers_by_vuln[new_key][0].append(
                                list(s[0]))
                            sanitizers_by_vuln[new_key][1] = "no"
                    else:
                        sanitizers_by_vuln[new_key] = [
                            [list(s[0])], "no"]
        else:
            if before_is_sanitizer[0] != parent["func"]["id"]:
                if expr_target != "":
                    sanitizers_by_vuln[new_key] = [
                        list(parent["func"]["id"]), "no"]
                else:
                    new_key = (''+source, ''+parent["func"]["id"])
                    sanitizers_by_vuln[new_key] = [
                        [list(before_is_sanitizer[0])], "no"]