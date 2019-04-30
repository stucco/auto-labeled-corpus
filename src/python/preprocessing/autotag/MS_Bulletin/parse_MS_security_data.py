# This script parses the information in the MS security data xml files and outputs the information
# in a graphson file.

import os, json, codecs, csv, calendar, re
import xml.etree.ElementTree as etree

def update_vuln_dict(section_name,subsection,vuln_dict):
    subsection_desc = subsection.get("Type")
    if subsection_desc is not None:
        dict_key = "MS-" + subsection_desc + "Description"
    else:
        dict_key = "MS-" + section_name + "Description"
    dict_key = dict_key.replace(' ','')
    description = subsection.find("{0}Description".format(namespace2))
    if description is not None:
        description = description.text
        if description is not None:
            description = description.replace('\n','')
            description = description.replace('         ','').strip()
            if dict_key in vuln_dict.keys():
                vuln_dict[dict_key].append(description)
            else:
                vuln_dict[dict_key] = [description]
    return vuln_dict

def date_to_epoch(date):
    # Check if there is an additional part added to the time
    if date is not None:
        if len(date) > 19:
            date1 = date[0:19]
            date2 = date[0:14]+date[-5:]
            date1 = date_to_epoch(date1)
            date2 = date_to_epoch(date2)
            return_dates = [str(date1), str(date2)]
            return return_dates
        else:
            date = re.split('[- : T]',date)
            for x in range(0,len(date)):
                date[x] = int(date[x])
            date = tuple(date)
            date = calendar.timegm(date)
            return str(date)

def jsonify(obj, outFile):
	json.dump(obj, codecs.open(outFile, 'w', encoding='utf-8'), separators=(',',':'), sort_keys=True, indent=4)  

# Get the file names
path = r'C:/Users/Corinne/Desktop/MS Security Data/'
in_path = path + 'MSRC-CVRF/'
files = os.listdir(in_path)

# Get the data from each file
file_num = 0
for file in files:
    #for file in ["ms13-051.xml"]:
    print file
    file_num = file_num + 1
    # Initialize the dictionaries and lists
    MSData = {}
    MSData["edges"] = []
    MSData["vertices"] = []
    MS_product_tree = {}
    # initialize a dictionary for each file
    file_dict = {}
    
    file_path = in_path + file
    tree=etree.parse(file_path)
    root=tree.getroot()

    namespace  = "{http://www.icasi.org/CVRF/schema/cvrf/1.1}"
    namespace1 = "{http://www.icasi.org/CVRF/schema/prod/1.1}"
    namespace2 = "{http://www.icasi.org/CVRF/schema/vuln/1.1}"

    # Document tracking section (meta data)
    document_tracking = root.find("{0}DocumentTracking".format(namespace))
    identification = document_tracking.find("{0}Identification".format(namespace))
    id = identification.find("{0}ID".format(namespace))
    alias = identification.find("{0}Alias".format(namespace))
    file_dict["MS-ID"] = id.text + "[" + alias.text + "]"
    file_dict["MS-Status"] = document_tracking.find("{0}Status".format(namespace)).text
    file_dict["MS-Version"] = document_tracking.find("{0}Version".format(namespace)).text
    revision = document_tracking.find("{0}RevisionHistory".format(namespace)).find("{0}Revision".format(namespace))
    file_dict["MS-RevisionNumber"] = revision.find("{0}Number".format(namespace)).text
    date = date_to_epoch(revision.find("{0}Date".format(namespace)).text)
    if isinstance(date,basestring) == True:
        date = [date]
    file_dict["MS-RevisionDate"] = date
    file_dict["MS-RevisionDescription"] = revision.find("{0}Description".format(namespace)).text
    date = date_to_epoch(document_tracking.find("{0}InitialReleaseDate".format(namespace)).text)
    if isinstance(date,basestring) == True:
        date = [date]
    file_dict["MS-InitialReleaseDate"] = date
    date = date_to_epoch(document_tracking.find("{0}CurrentReleaseDate".format(namespace)).text)
    if isinstance(date,basestring) == True:
        date = [date]
    file_dict["MS-CurrentReleaseDate"] = date
    
    # Document notes section
    document_notes = root.find("{0}DocumentNotes".format(namespace))
    if document_notes is not None:
        for note in document_notes.findall("{0}Note".format(namespace)):
            if note.get('Title') == 'Executive Summary':
                file_dict["MS-ExecutiveSummary"] = note.text

    # Aggregate Severity    
    file_dict["MS-AggregateSeverity"] = root.find("{0}AggregateSeverity".format(namespace)).text

    # Product Tree section
    for product in root.find("{0}ProductTree".format(namespace1)).findall("{0}FullProductName".format(namespace1)):
        MS_product_tree[product.get("ProductID")] = product.text

    # Vulnerability section
    CVE_data = []
    # Descriptions for each vulnerability
    for vulnerability in root.findall("{0}Vulnerability".format(namespace2)):
        vuln_note_number = 0
        vuln_dict = {}
        CVE_id = vulnerability.find("{0}CVE".format(namespace2))
        # Get ordinal and CVE numbers for this vulnerability
        ordinal_num = int(vulnerability.get("Ordinal"))
        if CVE_id is not None:
            vuln_dict["_id"] = CVE_id.text
        # Title for the vulnerability
        vuln_title = vulnerability.find("{0}Title".format(namespace2))
        if vuln_title is not None:
            vuln_dict["MS-Title"] = vuln_title.text
        # General notes for this vulnerability
        for notes in vulnerability.findall("{0}Notes".format(namespace2)):
            for note in notes.findall("{0}Note".format(namespace2)):
                if "MS-Description" in vuln_dict.keys():
                    vuln_dict["MS-Description"] = vuln_dict["MS-Description"].append(note.text)
                else:
                    vuln_dict["MS-Description"] = [note.text]
                vuln_note_number = vuln_note_number + 1
        # Descriptions
        impact_note_num = 0
        exploit_status_num = 0
        target_set_num = 0
        for section_name in ["Threats", "Remediations", "Acknowledgments"]:
            find_section = "{0}" + section_name
            for section in vulnerability.findall(find_section.format(namespace2)):
                find_subsection = "{0}" + section_name[:-1]
                for subsection in section.findall(find_subsection.format(namespace2)):
                    vuln_dict = update_vuln_dict(section_name,subsection,vuln_dict)
                    # If there are URLs, add them to a reference section
                    url = subsection.find("{0}URL".format(namespace2))
                    if url is not None and url.text is not None:
                        url = url.text
                        if "MS-References" in vuln_dict.keys():
                            vuln_dict["MS-References"].append(url)
                        else:
                            vuln_dict["MS-References"] = [url]
                    # If it's a remediation subsection, look for another remediation section within it
                    # to get the vendor fixes
                    for subsubsection in subsection.findall(find_subsection.format(namespace2)):
                        vuln_dict = update_vuln_dict(section_name,subsubsection,vuln_dict)

                    # If it's an acknowledgment section, get the acknowledgment name
                    if section_name == "Acknowledgments":
                        dict_key = "MS-AcknowledgmentName"
                        name = subsection.find("{0}Name".format(namespace2))
                        if name is not None:
                            name = name.text.strip()
                            if dict_key in vuln_dict.keys():
                                vuln_dict[dict_key].append(name)
                            else:
                                vuln_dict[dict_key] = [name]
                    
        # Append the meta data
        vuln_dict.update(file_dict)
        vuln_dict["_type"] = "vertex"
        if "_id" not in vuln_dict.keys():
            vuln_dict["_id"] = ""

        # Append the current vulnerability to the set of vertices for the MS data
        MSData["vertices"].append(vuln_dict)

        # Remove keys if their values are null/none
        for CVE in range(0,len(MSData["vertices"])):
            for key in MSData["vertices"][CVE].keys():
                if MSData["vertices"][CVE][key] == "None" or MSData["vertices"][CVE][key] is None:
                    del MSData["vertices"][CVE][key]


    # Output the results
    jsonify(MSData,path+'MSSecurityData' + str(file_num) + '.graphson')                    

"""# Input the information from the Excel file
# It was determined that we don't need this data
# Read in the data
filename = 'BulletinSearch_20130610_153248.csv'
with open(path + filename) as csv_file:
    reader = csv.reader(csv_file, delimiter=',', quotechar='"')
    var_names = []
    row_num = -1
    xls_vertices = []
    for row in reader:
        row_num = row_num + 1
        # Get the header row
        if row[0] == "Date\nPosted":
            for var in range(0,len(row)):
                if row[var] in var_names:
                    row[var] = row[var] + "2"
                row[var] = re.sub(' ','',row[var])
                row[var] = re.sub('\n','',row[var])
                var_names.append(row[var])
        # Get the data
        else:
            # Get the CVE number
            CVE_location = var_names.index("CVEs")
            CVEs = row[CVE_location]
            CVEs = re.split(',',CVEs)
            for i in range(0,len(CVEs)):
                # Store the data as one vertex for each CVE id in each row
                CVE_dict = {}
                for var in range(0,len(row)-1):
                    CVE_dict[var_names[var]] = row[var]
                    CVE_dict["_id"] = CVEs[i]
                    CVE_dict["_type"] = "vertex"
                del CVE_dict["Severity"]
                CVE_dict["References"] = ["http://technet.microsoft.com/en-us/security/bulletin/" + CVE_dict["BulletinID"],
                                          "http://support.microsoft.com/default.aspx?scid=kb;en-us;" + CVE_dict["BulletinKB"],
                                          "http://support.microsoft.com/default.aspx?scid=kb;en-us;" + CVE_dict["ComponentKB"]]
                if CVE_dict["References"][1] == CVE_dict["References"][2]:
                    del CVE_dict["References"][2]
                xls_vertices.append(CVE_dict)
    print var_names         
MSDataXLS = {}
MSDataXLS["edges"] = []
MSDataXLS["vertices"] = xls_vertices
jsonify(MSDataXLS,path+'MSSecurityDataXLS.graphson')
"""




