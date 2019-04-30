# This script reads in the metasploit data and saves it as a graphson file.

import json, codecs, os, csv, string, re, calendar

def date_to_epoch(date):
    date = re.split('[- :]',date)
    for x in range(0,len(date)):
        date[x] = int(date[x])
    date = tuple(date)
    date = calendar.timegm(date)
    return date

def get_metasploit_data(filepath,filename):
    # Initialize a dictionary containing the information
    metasploit_data = {}
    metasploit_data["edges"] = []
    metasploit_data["vertices"] = []
    var_names = []

    # Read in the data
    with open(filepath + '/' + filename) as csv_file:
        reader = csv.reader(csv_file, delimiter=',', quotechar='"')
        for row in reader:
            exploit = {}
            # Get the header row
            if row[0] == "id":          
                for var in row:
                    # Rename variables to what they are supposed to be in the output
                    var = string.capwords(var, '_')
                    var = var.replace('_','')
                    var = "Metasploit-" + var
                    var_names.append(var)
            # Get the data
            else:
                for var in range(0,len(row)):
                    # Fix the encoding: convert from iso-8859-1 to utf-8 
                    # (there might be special characters in the file that it can't decode)
                    row[var] = row[var].decode("iso-8859-1").encode("utf-8")
                    row[var] = row[var].replace('\t','')
                    row[var] = row[var].replace('\n',' ')
                    # Dictionary for each exploit
                    # Convert the date to epoch time
                    if (var_names[var] == "Metasploit-Mtime" or var_names[var] == "Metasploit-DisclosureDate") and row[var] != '':
                        row[var] = date_to_epoch(row[var])                  
                    exploit[var_names[var]] = row[var]
                    if var_names[var] == "Metasploit-RefNames":
                        CVE_id = re.findall(r"CVE-[0-9]{4}-[0-9]{4}",row[var])
                        exploit["Metasploit-CVEid"] = CVE_id
                        """BID_id = re.findall(r"BID-[0-9]+",row[var])
                        exploit["Metasploit-BIDid"] = BID_id"""
                        OSVDB_id = re.findall(r"OSVDB-[0-9]+",row[var])
                        exploit["Metasploit-OSVDBid"] = OSVDB_id
                        """EDB_id = re.findall(r"EDB-[0-9]+",row[var])
                        exploit["Metasploit-EDBid"] = EDB_id"""
                # Add the "_type" key and "_id" key to the dictionary
                exploit["_type"] = "vertex"
                exploit["_id"] = ""
                # Add this exploit to the set of nodes
                metasploit_data["vertices"].append(exploit)

    # Add the edges
    edge_num = 0
    for i in range(0,len(metasploit_data["vertices"])):
        V = metasploit_data["vertices"][i]
        for j in range(0,len(V["Metasploit-CVEid"])):
            metasploit_data["edges"].append({})
            metasploit_data["edges"][edge_num]["_id"]    = V["Metasploit-CVEid"][j] + "_to_" + V["Metasploit-Fullname"]
            metasploit_data["edges"][edge_num]["_inV"]   = V["Metasploit-CVEid"][j]
            metasploit_data["edges"][edge_num]["_label"] = "exploits"
            metasploit_data["edges"][edge_num]["_outV"]  = V["Metasploit-Fullname"]
            metasploit_data["edges"][edge_num]["_type"]  = "edge"
            metasploit_data["edges"][edge_num]["source"] = "Metasploit"
            edge_num = edge_num + 1        
        for j in range(0,len(V["Metasploit-OSVDBid"])):
            metasploit_data["edges"].append({})
            metasploit_data["edges"][edge_num]["_id"]    = V["Metasploit-OSVDBid"][j] + "_to_" + V["Metasploit-Fullname"]
            metasploit_data["edges"][edge_num]["_inV"]   = V["Metasploit-OSVDBid"][j]
            metasploit_data["edges"][edge_num]["_label"] = "exploits"
            metasploit_data["edges"][edge_num]["_outV"]  = V["Metasploit-Fullname"]
            metasploit_data["edges"][edge_num]["_type"]  = "edge"
            metasploit_data["edges"][edge_num]["source"] = "Metasploit"
            edge_num = edge_num + 1            

    # Output the data
    jsonify(metasploit_data, filepath + "/" + "Metasploit_data3.graphson")

# Output the data in the proper format
def jsonify(obj, outFile):
    json.dump(obj, codecs.open(outFile, 'w', encoding='utf-8'),
    separators=(',',':'), sort_keys=True, indent=4)    

# file path where the data is stored and where the graphson file will be outputted
filepath = r'C:/Users/Corinne/Desktop/Metasploit Data'
filename = 'module_details_authors_refs.csv'
get_metasploit_data(filepath,filename)



            
                
