import subprocess
import re
from subprocess import DEVNULL


class DetectionRuleConverter(object):

    @staticmethod
    def convertSigmaRule(sigma_path, sigma_config_path, rule_path):
        command = [sigma_path + ' -t splunk ' + sigma_config_path + ' ' + rule_path]
        sigma_search = subprocess.run(
            command, shell=True, stdout=subprocess.PIPE, stderr=DEVNULL, universal_newlines=True)
        sigma_search_output = sigma_search.stdout
        commandfieldlist = [sigma_path + ' -t fieldlist ' + sigma_config_path + ' ' + rule_path]
        sigma_search_fieldlist = subprocess.run(
            commandfieldlist, shell=True, stdout=subprocess.PIPE, stderr=DEVNULL, universal_newlines=True)
        sigma_search_fields_output = sigma_search_fieldlist.stdout

        if sigma_search.returncode != 0:
            print("# Failure converting the Sigma File: " + rule_path)
            return "Converter Failure"
        else: 
            sigma_search_dict = {'search': '', 'fields': []}
            length = len(sigma_search_output.splitlines())
            if length == 1:
                sigma_search_dict['search'] = sigma_search_output
            elif length > 1:
                search = sigma_search_output.splitlines()[0]
                table = ""
                countCmd = search.count("|")
                if countCmd > 1:
                    sigma_search_multiline_output = search
                elif countCmd==1 and "| table" in search:
                    tableindex = search.find('| table')
                    sigma_search_multiline_output = search[:tableindex]
                    table = search[tableindex:]
                else:
                    sigma_search_multiline_output = " ( "+search+" ) "
                for i in range(1, length):
                    search = sigma_search_output.splitlines()[i]
                    countCmd = search.count("|")
                    if countCmd > 1:
                        sigma_search_multiline_output = sigma_search_multiline_output + " | append [ search " + search + " ] "
                    elif countCmd==1 and "| table" in search:
                        tableindex = search.find('| table')
                        sigma_search_multiline_output = sigma_search_multiline_output + " OR ( " + search[:tableindex] + " ) "
                        table += search[tableindex:]
                    else:
                        sigma_search_multiline_output = sigma_search_multiline_output + " OR ( " + search + " ) "
                if table:
                    outputTable=[]
                    for field in table.replace("| table ",",").split(","):
                        if field and field not in outputTable:
                            outputTable.append(field)
                    sigma_search_multiline_output += "| table "+' '.join(outputTable)
                sigma_search_dict['search'] = sigma_search_multiline_output
            if sigma_search_fields_output:
                sigma_search_dict['fields'] = sigma_search_fields_output.splitlines()
            return sigma_search_dict
    
    @staticmethod
    def addSearchFilter(initial_filter, search, sigma_rule):
        search = initial_filter + " " + search
        if '| append [ search ' in search:
            search = search.replace('| append [ search ','| append [ search ' + initial_filter)
        search = search.replace("%RULE_NAME%",sigma_rule["title"])
        return search

    @staticmethod
    def addToSummaryIndex(search, sigma2splunkalertconfig, sigma_rule):
        if "summary_index" in sigma2splunkalertconfig["alert_action"]:
            summaryindexconfig = sigma2splunkalertconfig["alert_action"]["summary_index"]
            search = search[:-1] + ' | rename _time as orig_time, rawHash as orig_rawHash, index as orig_index, sourcetype as orig_sourcetype, host as orig_host, count as orig_count | search NOT([| search `sigma_matches` source="'+sigma_rule["title"]+'" | stats count by orig_time orig_time_end orig_rawHash | fields orig_time orig_time_end orig_rawHash ]) | addinfo | rename info_search_time as _time | fields - info_* | collect index=' + \
                summaryindexconfig["name"]
            if ("enrich_tags" in summaryindexconfig) or ("enrich_level" in summaryindexconfig):
                search = search + ' marker="'
                if "enrich_tags" in summaryindexconfig:
                    if "tags" in sigma_rule:
                        for tag in sigma_rule["tags"]:
                            if re.match('attack.t[0-9]+$',tag):
                                search = search + "attack_ID=" + tag[7:] + ","
                            elif re.match('attack.g[0-9]+$',tag):
                                search = search + "attack_group_id=" + tag[7:] + ","
                            elif re.match('attack.[a-z_]+$',tag):
                                search = search + "attack_tactics=" + tag[7:].replace("_","-") + ","
                            else:
                                search = search + "sigma_tag='" + tag + "',"
                if "enrich_level" in summaryindexconfig:
                    if "level" in sigma_rule: 
                        search = search + "level=" + sigma_rule["level"]
                    else:
                        search = search + "level=low"
                        print("# Warning Sigma Rule: " + sigma_rule["title"] + " no level found default to low")
                if search[-1:] == ",":
                    search = search[:-1]
                search = search + '"'
        return search

    @staticmethod
    def performSearchTransformation(transformations, search, fields, sigma_rule):
        for trans in transformations:

            # Search Transformation to add whitelist in front of table or transforming command (for better whitelisting)
            if trans == "add_whitelist_in_front":
                file_name = sigma_rule["title"] + "_whitelist.csv"
                file_name = file_name.replace(" ", "_")
                file_name = file_name.replace("/", "_")
                file_name = file_name.replace("(", "")
                file_name = file_name.replace(")", "")
                if '| table' in search:
                    tableindex = search.find('| table')
                    search = search[:tableindex] + "| search NOT [| inputlookup " + \
                        file_name + "] " + search[tableindex:]
                elif '| stats' in search:
                    statsindex = search.find('| stats')
                    search = search[:statsindex] + "| search NOT [| inputlookup " + \
                        file_name + "] " + search[statsindex:]
                else:
                    search = search[:-1] + " | search NOT [| inputlookup " + file_name + "] "

            # Search Transformation to add whitelist at the end of the search
            if trans == "add_whitelist":
                file_name = sigma_rule["title"] + "_whitelist.csv"
                file_name = file_name.replace(" ", "_")
                file_name = file_name.replace("/", "_")
                file_name = file_name.replace("(", "")
                file_name = file_name.replace(")", "")
                search = search[:-1] + " | search NOT [| inputlookup " + file_name + "] "
                
            if trans == "add_table" and not "| table" in search:
                search = search[:-1] + " | table "
                

            # Search Tranformation to add fields
            if re.match(r"add_\w+_field", trans):
                findTables = re.findall(r" \|\s+table\s+[^\|\]]*", search)
                findTablesIdx = [(m.start(0), m.end(0)) for m in re.finditer(r" \|\s+table\s+[^\|\]]*", search)]
                newTables = []
                for table in findTables:
                    if table:
                        newTable = table.rstrip("\n\r")
                        if trans == "add_time_field" and not re.match('.*[, ]_time[, ].*',table):
                            newTable += ' _time'    
                        if trans == "add_host_field" and not re.match('.*[, ]host[, ].*',table):
                            newTable += ' host'     
                        if trans == "add_source_field" and not re.match('.*[, ]source[, ].*',table):
                            newTable += ' source'
                        if trans == "add_sourcetype_field" and not re.match('.*[, ]sourcetype[, ].*',table):
                            newTable += ' sourcetype'
                        if trans == "add_index_field" and not re.match('.*[, ]index[, ].*',table):
                            newTable += ' index'
                        if trans == "add_rawHash_field" and not re.match('.*[, ]rawHash[, ].*',table):
                            newTable += ' rawHash'
                        if fields and trans == "add_FIELDLIST_field":
                            for field in fields:
                                if not re.match('.*[, ]'+field+'[, ].*',table):
                                    newTable += ' '+field
                        newTables.append(newTable)
                updatedSearch = ""
                offset = 0
                for i in range(len(findTablesIdx)):
                    updatedSearch = search[:findTablesIdx[i][0]+offset] + newTables[i] + search[findTablesIdx[i][1]+offset:]
                    offset+=len(newTables[i]) - (findTablesIdx[i][1]-findTablesIdx[i][0])
                
                    search = updatedSearch
                
            if trans == "add_transforming_command":
                findTables = re.findall(r" \|\s+table\s+[^\|\]]+", search)
                findTablesIdx = [(m.start(0), m.end(0)) for m in re.finditer(r"\|\s+table\s+[^\)\|\]]+", search)]
                newTables = []
                for table in findTables:
                    if table:
                        table = table.rstrip("\n\r").replace(","," ")
                        fillnullCmd= table.replace(' table ',' fillnull value="" ')
                        groupingFieldArray= table.replace(" | table ","").split(" ")
                        groupingFieldArray.remove('_time')
                        groupingFieldArray.remove('rawHash')
                        groupingFieldStr = " ".join(groupingFieldArray)
                        newTable = table + fillnullCmd +' | stats count earliest(_time) as _time latest(_time) as orig_time_end earliest(rawHash) as rawHash by '+groupingFieldStr+' '
                        newTables.append(newTable)
            
                updatedSearch = ""
                offset = 0
                for i in range(len(findTablesIdx)): 
                    updatedSearch = search[:findTablesIdx[i][0]+offset] + newTables[i] + search[findTablesIdx[i][1]+offset:]
                    offset+=len(newTables[i]) - (findTablesIdx[i][1]-findTablesIdx[i][0])
            
                    search = updatedSearch                                
               

            # Add Custom Search Transformations here

        return search
