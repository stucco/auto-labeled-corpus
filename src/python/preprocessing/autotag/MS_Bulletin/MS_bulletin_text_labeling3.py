# MS_bulletin_text_labeling3.py

from collections import defaultdict
import json, re, pickle, nltk
import copy
import os
import codecs
import numpy as np 

#debug = True

path = r'C:/Users/Corinne/Desktop/MS Security Data/MS_Security_Graphson_Files/'
path2 = r'C:/Users/Corinne/Desktop/MS Security Data/'
#files = ['MSSecurityData90.graphson']
files = os.listdir(path)

path_train="/MS_bulletin.train.graphson" # output path, a "cveid":"tagged sentence" dictionary
path_out=path2+"/MS_bulletin_w_tags.graphson" # output path, the same graphson file, for all 4 years w/ a new value "tagged" and the tagged text saved

path_out_sample=path2+"/random_sample" # used for validation.  Writes randomly sampled cve entries w/ tags to .txt file.  I then hand-checked these.  

# # take .json files into python dict
obj = {}
for file_num in range(0,len(files)):
    obj_text = codecs.open(path+files[file_num], 'r', encoding='utf-8').read()
    current_obj = json.loads(obj_text)
    obj[file_num] = current_obj

####### Make a dictionary of the corpus tagged and pos_tagged ########

def both_tags():
    """
    returns a dictionary, obj, with a key for each year.  obj[year] is 
    the graphson file dictionary.  This adds a new field, "tagged_text", 
    which is a triple, the word, the NVD-tag, and the POS-tag
    """
    obj = {}
    files = os.listdir(path)
    #files = ['MSSecurityData90.graphson']
    
    for file_num in range(0,len(files)):
        obj_text = codecs.open(path+files[file_num], 'r', encoding='utf-8').read()
        current_obj = json.loads(obj_text)
        obj[file_num] = current_obj

    for file_num in xrange(0,len(files)):
        print file_num
        print files[file_num]
        for j in xrange(len(obj[file_num]["vertices"])):
            obj[file_num]["vertices"][j]["tagged_text"] = []
            t = ""
            # Combine the descriptions in a given file
            for description in ['MS-Description','MS-ExecutiveSummary','MS-ImpactDescription','MS-MitigationDescription',
                                'MS-TargetSetDescription','MS-Title', 'MS-WorkaroundDescription']:
                V=obj[file_num]["vertices"][j]
                if description in V.keys():
                    if description == 'MS-Title' or description == 'MS-ExecutiveSummary':
                        V[description]= [V[description]]
                    for i in range(0,len(V[description])):
                        t = t + ' ' + V[description][i]
            # Perform the tagging         
            if V["_id"] != '':
                t=t.split(' ')
                ID=V["_id"]
                T,keep=basic_tagger(t,ID)
                if keep==1: # only keep it if it found a matching cpe vector
                    T=secondary_tagger(T)
                    S=nltk.untag(T)
                    S=nltk.pos_tag(S)
                    for i in range(len(T)):
                        T[i]=(T[i][0], T[i][1], S[i][1])
                    obj[file_num]["vertices"][j]["tagged_text"].extend(T)
        print "done with file ", file_num
    print "Done"
    return obj


def jsonify(obj, outFile):
	json.dump(obj, codecs.open(outFile, 'w', encoding='utf-8'), separators=(',',':'), indent=4, sort_keys=True)  

#The output of "tagged_corpus_dict" is what I saved as path_train
def tagged_corpus_dict():
    """
    Takes the dictionary output of both_tags(), and makes a returns a new dictionary named "tagged".
    Its keys are cveids and its values are the tagged sequence (list of triples) for that year.    
    """	
    tagged={}
    V = {}
    for val in range(0,len(files)):
        File = path2 + 'labeling_output/file' + str(val) + '.graphson'
        obj_text = codecs.open(File, 'r', encoding='utf-8').read()
        new_obj = json.loads(obj_text)        
        obj[val] = new_obj

    path_out=path2+"MS_bulletin_w_tags.graphson"	
    for file_num in obj.keys():
        print file_num
        for j in xrange(len(obj[file_num]["vertices"])):
            V=obj[file_num]["vertices"][j]
            ID=V["_id"]
            tagged[ID]=V["tagged_text"]
        print "done with ", file_num
    return tagged

######## randomly sample from list #########

def sample2(n, path_out_sample):
    """
    Randomly samples n tagged descriptions from the initial .graphson files (nvd nodes)
    then tags their text and writes them to a .txt file w/ path "path_out_sample"
    """
    A=[]
    obj = {}
    files = os.listdir(path)
    
    for file_num in range(0,len(files)):
        obj_text = codecs.open(path+files[file_num], 'r', encoding='utf-8').read()
        current_obj = json.loads(obj_text)
        obj[file_num] = current_obj
        for j in xrange(len(current_obj["vertices"])):
            A.append((file_num,j))
    out=open(path_out_sample, "w")
    sample_list = []

    num_samples = 0
    while num_samples < 25:                         
        np.random.shuffle(A) # replaces A w/ a jumbled version
        #print A[0]
        (file_num,j)=A[0]

        # tag it
        V=obj[file_num]["vertices"][0]
        t = ""
        if V["MS-ID"] not in sample_list:
            sample_list.append(V["MS-ID"])  
            # Combine the descriptions in a given file
            for description in ['MS-Description','MS-ExecutiveSummary','MS-ImpactDescription','MS-MitigationDescription',
                                'MS-TargetSetDescription','MS-Title', 'MS-WorkaroundDescription']:
                V=obj[file_num]["vertices"][0]
                if description in V.keys():
                    if description == 'MS-Title' or description == 'MS-ExecutiveSummary':
                        V[description]= [V[description]]
                    for i in range(0,len(V[description])):
                        t = t + ' ' + V[description][i]
                        
            t=t.split(' ')
            ID=V["_id"]
            T,keep=basic_tagger(t,ID)
            if keep==1:
                num_samples = num_samples+1
                print num_samples
                T=secondary_tagger(T)

                out.write(ID+" "+str(j)+"\n")

                # s=""
                for (word,tag) in T:
                    # s+=" "+word+" "+tag
                    word = word.encode("utf-8")
                    out.write(word+" "+tag+"\n")
                out.write("\n")
    out.close()
    print "DONE!"


A=[(2010, 69),(2012,2947), (2012,3345),(2011,344), (2011,1641)] 

def sanitize(t):
    """
    t is a list of words.  Often words will have stranded parens, eg
    "(also" or "end)" .  This removes stranded whitespace and puntuation
    """
    j=0
    while j < len(t):
        if t[j]!="" and t[j]!=".NET":
            t[j]=t[j].strip() # removes leading and ending whitespaces
            if not re.search(r'\(\)$', t[j]):
                if re.search(r'^[!,:;.()?@\%\[\]\'\"]{1}[a-zA-Z0-9]{1,}\.?', t[j]):
                    t=t[0:j]+[t[j][0]]+[t[j][1:]]+t[j+1:]
                    if j!=0:
                        j=j-1
                if 	re.search(r'[a-zA-Z0-9.]{1,}[!,.;:()?@\%\[\]\'\"]{1}$', t[j])  and t[j].lower()!="joomla!" and t[j].lower()!="yahoo!":
                    t=t[0:j]+[t[j][:-1]]+[t[j][-1]]+t[j+1:]
                    if j!=0:
                        j=j-1
                # Split ending punctuation where there's ")." or "),"
                if re.search(r'[a-zA-Z0-9.]{1,}[)\'\"]{1}[,.]{1}$', t[j]):
                    t=t[0:j]+[t[j][:-1]]+[t[j][-1]]+t[j+1:]
                    if j!=0:
                        # if it finds punctuation to remove, decrease j so it looks at it again
                        j=j-1
        elif t[j]=="":
            del t[j]
            j = j-1
                
        j=j+1
    return t

def surroundings(t,j,n):
	""" 
	t is a list, j is an index, n is the number of words 
	requested before and after t[j]
	"""
	a=max(0,j-n)
	b=min(len(t), j+n)
	return t[a:b+1]


def basic_tagger(t, ID):
    """
    t= V["description"].split(' ') for V in obj["vertices"], it's
     a list of words to be tagged.
    ID=V["_id"]
    tags come from the cpe vector.  This function gets the cveid, the looks 
    for any edge (in the nvd nodes/edges .graphson file) to a cpe node.  Takes
    the cpe vector from there and autotags the text for that cveid.  
    """
    #year=int(ID.split("-")[1])
    t=sanitize(t)
    tt=range(len(t)) # tt will be the lowercase version of t
    for j in xrange(len(t)):
        tt[j]=t[j].lower()

    # Get the edges from the nvdcve file so we have the cve-cpe correspondence
    cve_objs = {}
    cve_objs["edges"] = []
    cve_objs["vertices"] = []
    for year in range(2010,2014):
        cve_file = path2 + 'NVD files/nvdcve-2.0-' + str(year) + '.graphson'
        obj_text = codecs.open(cve_file, 'r', encoding='utf-8').read()
        cve_obj = json.loads(obj_text)
        cve_objs["edges"].extend(cve_obj["edges"])

    A=[e for e in cve_objs["edges"] if e["_id"].split("_to_")[0]==ID]	
    # A is the list of corresponding cpe nodes

    B=defaultdict(lambda : "O")
    B[2]="vendor"
    B[4]="version"
    B[5]="update"
    B[6]="edition"
    B[7]="language"
    # B is a dict mapping the index of v to the labels the entries of v

    # C=[] # list of regexs used in versioning for this text
    # regexs=['^[0-9\.]+\-[0-9a-zA-Z\.]$','^[0-9\.]+[.a-zA-z]*$',	'^[0-9\.]+_[a-zA-Z0-9]*$',	'^[0-9\.]+\%[0-9a-zA-Z]*$']


    T=range(len(t)) # the output list, a list of tuples of the form 
                    # (word, tag) 

    # initialize T as every word has tag "O" the null tag
    for j in xrange(len(T)):
        T[j]=(t[j], "O")

    for e in A:
        v=e["_id"].split("_to_")[1].split(":")
        # v is the cpe vector
        
        if v[1]=="/a":
            B[3]="application"
            # B[tuple(v[3].split("_"))]="application"
        if v[1]=="/h":
            B[3]="hardware"
            # B[v[3]]="hardware"
        if v[1]=="/o":
            B[3]="os"
            # B[v[3]]="os"

        u=range(len(v)) # if v[j] is 2 words, they are connected with "_", for example
                        # v[j]="http_server".  u gives the same list as v, with tuples
                        # for entries w/ more than word, eg. u[j]=("http", "server")
        for j in xrange(len(v)):
            u[j]=tuple(v[j].split("_"))

        # Store the application names so have a list of them to tag with later
        # application_names = [] <- this should be in the main program
        # if tuple(v[3].split("_")) not in application_names:
        #   application_names.extend(tuple(v[3].split("_")))
        # return application_names at the end of the function
        #
        # def tag_application_names(T,ID,application_names):
        #   for j in xrange(len(T)):
        #       t[j] = T[j].lower()
        #   for app in application_names:
        #       app_length = len(app)
        #       for i in range(0,len(t)+1-app_length):
        #           for j in range(i,i+app_length):
        #                           

        #the loop below tags the sentence
        for j in xrange(2,len(u)): # u[1]=('cpe',) always, and u[2]=(x,) w/ x="/a", "/h", "/o" 	
            n=len(u[j])
            if n==1:
                for i in xrange(len(tt)):
                    if tt[i]==u[j][0] or tt[i]==u[j][0]+"'s":
                        T[i]=(t[i], "B:"+B[j])
            if n>1:
                for i in xrange(len(tt)-n):
                    if tuple(tt[i:i+n])==u[j] or tt[i:i+n]==u[j][0]+"'s":
                        T[i]=(t[i], "B:"+B[j])
                        for k in xrange(i+1,i+n):
                            T[k]=(t[k],"I:"+B[j])
    if A is None or A==[]:
        return T,0
    else:
        return T,1

def secondary_tagger(T):
    """
    regexs for tagging
    """
    # for version tagging regexs
    C=[r'^[0-9]+(\.|x)+[0-9a-zA-Z\-\.]{1,}$' ,r'^[0-9.x]{2,}\.+-[0-9a-zA-Z.]+$',r'^[0-9\.x]+\.?[a-zA-Z.]+$',r'^[0-9\.x]+_[a-zA-Z0-9.]+$',r'^[0-9\.x]+\%[0-9a-zA-Z.]+$',r'^[0-9\.x]+-([0-9.]+[a-zA-Z0-9.\-_]*|[a-zA-Z0-9.\-_]*[0-9.]+)$',r'^v[0-9x\.\-]{2,}$']

    # Lists for cwe relevant term tagging
    ones=[("MITM"),('(csrf)',), ('(xss)',), ('..',), (u'CSRF',), (u'HTML',), (u'Integer',) ,("sql",) , (u'Race',), (u'Use-after-free',), (u'XSS',), (u'access',), (u'account',), (u'allows',), (u'application',), (u'arbitrary',), ('attack',), (u'attackers',), ('authenticate',), (u'authenticated',), ('authentication',), ('authorization',), (u'blocked',), (u'brute-force',), (u'bypass',), (u'cleartext',), (u'code',), (u'commands',), ('configuration',), (u'crash',), (u'credentials',), ('csrf',), ('ddos',), ('denial',), ('denial of service',), ('distributed denial of service',), ('dos',), (u'execute',), ('exposure',), (u'file.',), (u'files',), ('fingerprinting',), (u'forgery',), (u'gain',), (u'handlers',), (u'hijack',), (u'hook',), (u'hook-handler',), (u'information',), (u'inject',), (u'kernel',), (u'kernel-mode',), (u'local',), (u'malware',), ('man-in-the-middle',), (u'memory',), (u'metacharacters',), (u'obtain',), (u'obtained',), ('overflow',), ('overflows',), (u'overwrite',), (u'password',), ('permissions',), ('plaintext',), (u'privileges',), (u'remote',), (u'requests',), (u'script',), (u'scripting',), (u'sensitive',), (u'service',), ('sign',), (u'signature-based',), ('signedness',), (u'symlink',), ('truncation',), ('underflow',), ('underflows',), (u'user-space',), (u'value',), ('xss',)]
    twos=[('.', '.'), ("integer","underflow"),("Integer", "underflows"),(u'Race', u'condition'), (u'SQL', u'commands'), ('SQL', 'injection'), (u'Use-after-free', u'vulnerability'), ('access', 'control'), (u'access', u'restrictions'), (u'application', u'crash'), (u'arbitrary', u'SQL'), ('arbitrary', 'certificate'), ('arbitrary', 'code'), (u'arbitrary', u'files'), ('arbitrary', 'password'), ('authentication', 'issues'), ('buffer', 'error'), ('buffer', 'overflow'), (u'bypass', u'authentication'), ('code', 'injection'), ('credentials', 'management'), ('cross', 'site forgery'), ('cross-site', 'forgery'), ('cross-site', 'request'), ('cross-site', 'scripting'), ('cryptographic', 'issues'), ('design', 'error'), ('design', 'errors'), ('dot', 'dot'), ('finger', 'printing'), ('format', 'string'), ('gain', 'privileges'), ('hard', 'links'), ('infinite', 'loop'), ('infinite', 'loops'), ('information', 'disclosure'), ('information', 'leak'), ('inject', 'code'), (u'injection', u'vulnerability'), ('input', 'validation'), ('integer', 'overflow'), ('key', 'disclosure'), ('link', 'following'), (u'local', u'users'), ('memory', 'exhaustion'), ('memory', 'leak'), ('memory', 'leaks'), ('modify', 'query'), ('numeric', 'error'), ('numeric', 'errors'), ('path', 'traversal'), (u'potentially', u'sensitive'), ('race', 'conditions'), ('remote', 'attacker'), (u'remote', u'attackers'), ('replay', 'attack'), ('resource', 'management'), (u'sensitive', u'information'), ('sql', 'injection'), ('symbolic', 'links'), (u'symlink', u'attack'), (u'traversal', u'vulnerability'), ('weak', 'key'), (u'web', u'script')]
    threes=[(u'Directory', u'traversal', u'vulnerability'), (u'Multiple', u'cross-site', u'request'), (u'SQL', u'injection', u'vulnerabilities'), (u'SQL', u'injection', u'vulnerability'), (u'arbitrary', u'PHP', u'code'), (u'arbitrary', u'SQL', u'commands'), (u'arbitrary', u'web', u'script'), ('buffer', 'boundary', 'error'), ('cross', 'site', 'request'), ('cross', 'site', 'scripting'), ('cross-site', 'request', 'forgery'), (u'denial', u'of', u'service'), (u'execute', u'arbitrary', u'SQL'), ('execute', 'arbitrary', 'code'), (u'execute', u'arbitrary', u'commands'), (u'format', u'string', u'specifiers'), ('format', 'string', 'vulnerability'), ('gain', 'administrative', 'access'), (u'hijack', u'the', u'authentication'), ('inject', 'arbitrary', 'code'), ('modify', 'query', 'logic'), (u'obtain', u'sensitive', u'information'), ('os', 'command', 'injection'), (u'remote', u'authenticated', u'users'), ('resource', 'management', 'error'), ('resource', 'management', 'errors')]


    for j in xrange(len(T)):
        # version tagging:
        for regex in C:
            s,tag=T[j]
            if tag =="O" and re.search(regex,s):
                T[j]=(T[j][0],"B:version")
            #if j>0 and re.search(r'[0-9x\.\-]',T[j][0] ):
            if j>0 and re.search(r'([0-9x\-]){1,}|([0-9x\.\-]){2,}',T[j][0] ):
                if (T[j-1][0]=="before" or T[j-1][0]=="through") and not re.search(r'(\w[a-z\-]){2,}',T[j][0]):
                    if j>1 and re.search("version", T[j-2][1]):
                        T[j-1]=(T[j-1][0],"I:version")
                        T[j]=(T[j][0], "I:version")
                    else: 
                        T[j-1]=(T[j-1][0],"B:version")
                        T[j]=(T[j][0], "I:version")
                    if re.search("application", T[j-1][1]):
                        T[j]=(T[j][0], "B:version")
            if len(T)>j+1 and re.search(r'[0-9x\.\-]',T[j][0] ):
                if (T[j+1][0]=="and" or T[j+1][0]=="or") and T[j+2][0]=="earlier":
                    T[j]=(T[j][0], "B:version")
                    T[j+1]=(T[j+1][0],"I:version")
                    T[j+2]=(T[j+2][0], "I:version")
                if T[j+1][0]=="and" and T[j+2][0]=="below":
                    T[j]=(T[j][0], "B:version")
                    T[j+1]=(T[j+1][0],"I:version")
                    T[j+2]=(T[j+2][0], "I:version")

            if re.search("version", T[j][1]) and len(T)>j+2 and re.search(r'^[,]{1}$|^and$',T[j+1][0]) and re.search(r'^[0-9]',T[j+2][0]):
                T[j+2]=(T[j+2][0],"B:version")
            if re.search("version", T[j][1]) and len(T)>j+3 and T[j+1][0]=="," and T[j+2][0]=="and" and re.search(r'^[0-9]',T[j+3][0]):
                T[j+3]=(T[j+3][0],"B:version")
            if T[j][0]=="all" and len(T)>j+2 and T[j+1][0]=="supported" and (T[j+2][0]=="versions" or T[j+2][0]=="releases"):
                T[j] = (T[j][0],"B:version")
                T[j+1] = (T[j+1][0],"B:version")
                T[j+2] = (T[j+2][0],"B:version")
                

        # update tagging:
        if re.search(r'^[A-Z]{1,3}[0-9]$', T[j][0]) and T[j][1]=="O":
            A=surroundings(T, j, 3)[0:3]
            for s,tag in A:
                if tag=="B:version":
                    T[j]=(T[j][0],'B:update')
        if  re.search(r'^[0-9a-z\-_.]*\%[0-9a-z\-_.]+', T[j][0]) and T[j][1]=="O":
            T[j]=(T[j][0],'B:update')
        if re.search(r'^-[a-zA-Z0-9.]+$', T[j][0]) and T[j][1]=="O":
            T[j]=(T[j][0],'B:update')
        if re.search(r"^alpha[_0-9a-zA-Z.]+",T[j][0]) and T[j][1]=="O":
            T[j]=(T[j][0],'B:update')
        if re.search(r"^beta[_0-9a-zA-Z.]+",T[j][0]) and T[j][1]=="O":
            T[j]=(T[j][0],'B:update')
        if re.search(r"^pre[0-9a-zA-Z._-]+",T[j][0]) and T[j][1]=="O" and not re.search(r"^pre[a-z]+$",T[j][0]):
            T[j]=(T[j][0],'B:update')
        if re.search(r"^release[_\-a-zA-Z0-9]+",T[j][0]) and T[j][1]=="O":
            T[j]=(T[j][0],'B:update')	
        if re.search(r"^update[_\-a-zA-Z0-9]+",T[j][0]) and T[j][1]=="O" and not re.search(r"^update[a-z]+$",T[j][0]):
            T[j]=(T[j][0],'B:update')
        if re.search(r"\bbeta\b|\bBeta\b|\balpha\b|\bAlpha\b", T[j][0]):
            A=surroundings(T, j, 3)[0:3]
            for s,tag in A:
                if tag=="B:version":
                    T[j]=(T[j][0],'B:update')

        # cve_id_tagger 
        if re.search(r'CVE-[0-9]{4}-[0-9]{4}' , T[j][0]):
            T[j]=(T[j][0], "B:cve id")

        # cwe relevant term tagging
        if len(T)>j+2:
            for x,y,z in threes:
                if (T[j][0].lower(),T[j+1][0].lower(),T[j+2][0].lower())==(x.lower(),y.lower(),z.lower()):
                    if (T[j][1],T[j+1][1],T[j+2][1])==("O","O","O"):
                        T[j]=(T[j][0],"B:relevant_term")
                        T[j+1]=(T[j+1][0],"I:relevant_term")
                        T[j+2]=(T[j+2][0],"I:relevant_term")
        if len(T)>j+1:
            for x,y in twos:
                if (T[j][0].lower(),T[j+1][0].lower())==(x.lower(),y.lower()):
                    if (T[j][1],T[j+1][1])==("O","O"):
                        T[j]=(T[j][0],"B:relevant_term")
                        T[j+1]=(T[j+1][0],"I:relevant_term")
        for x in ones:
            if T[j][0].lower()==x[0].lower() and T[j][1]=="O":
                T[j]=(T[j][0],"B:relevant_term")

        # java terms tagger  
        if T[j][0]=="JavaScript":
            T[j]=(T[j][0],"B:programming language")
        if T[j][0].lower()=="java" and j!=0 and T[j-1][0].lower()=="oracle":
            T[j-1]=(T[j-1][0],"B:vendor")
            T[j]=(T[j][0],"B:application")
        if T[j][0].lower()=="java" and j!=0 and T[j-1][0].lower()=="sun":
            T[j-1]=(T[j-1][0],"B:vendor")
            T[j]=(T[j][0],"B:application")
        if T[j][0].lower()=="java" and len(T)>j+2 and T[j+1][0].lower()=="runtime" and T[j+2][0].lower()=="environment":
            T[j]=(T[j][0],"B:application")
            T[j+1]=(T[j+1][0],"I:application")
            T[j+2]=(T[j+2][0],"I:application")
            if len(T)>j+3 and re.search(r'^[0-9.\-_]+$',T[j+3][0]):
                T[j+3]=(T[j+3][0],"B:version")
        if T[j][0].lower()=="java" and len(T)>j+2 and T[j+1][0].lower()=="web" and T[j+2][0].lower()=="start":
            T[j]=(T[j][0],"B:application")
            T[j+1]=(T[j+1][0],"I:application")
            T[j+2]=(T[j+2][0],"I:application")
            if len(T)>j+3 and re.search(r'^[0-9.\-_]+$',T[j+3][0]):
                T[j+3]=(T[j+3][0],"B:version")
        if T[j][0].lower()=="java" and len(T)>j+1 and T[j+1][0].lower()=="plug-in":
            T[j]=(T[j][0],"B:application")
            T[j+1]=(T[j+1][0],"I:application")
            if len(T)>j+2 and re.search(r'^[0-9.\-_]+$',T[j+2][0]):
                T[j+2]=(T[j+2][0],"B:version")

        if T[j][0].lower()=="java" and len(T)>j+1 and T[j+1][0].lower()=="se":
            T[j]=(T[j][0],"B:application")
            T[j+1]=(T[j+1][0],"I:application")
            if len(T)>j+2 and re.search(r'^[0-9.\-_]+$',T[j+2][0]):
                T[j+2]=(T[j+2][0],"B:version")
        if T[j][0].lower()=="java" and len(T)>j+1 and T[j+1][0].lower()=="ee":
            T[j]=(T[j][0],"B:application")
            T[j+1]=(T[j+1][0],"I:application")
            if len(T)>j+2 and re.search(r'^[0-9.\-_]+$',T[j+2][0]):
                T[j+2]=(T[j+2][0],"B:version")
        if T[j][0].lower()=="java" and len(T)>j+1 and T[j+1][0].lower()=="me":
            T[j]=(T[j][0],"B:application")
            T[j+1]=(T[j+1][0],"I:application")
            if len(T)>j+2 and re.search(r'^[0-9.\-_]+$',T[j+2][0]):
                T[j+2]=(T[j+2][0],"B:version")
        if T[j][0].lower()=="java" and len(T)>j+2 and T[j+1][0].lower()=="for" and T[j+2][0].lower()=="business":
            T[j]=(T[j][0],"B:application")
            T[j+1]=(T[j+1][0],"I:application")
            T[j+2]=(T[j+2][0],"I:application")
            if len(T)>j+3 and re.search(r'^[0-9.\-_]+$',T[j+3][0]):
                T[j+3]=(T[j+3][0],"B:version")
        if re.search(r'^j2se[0-9]*$' , T[j][0].lower()):
            T[j]=(T[j][0],"B:application")
        if T[j][0].lower()=="java" and len(T)>j+2 and T[j+1][0].lower()=="system" and T[j+2][0].lower()=="web":
            T[j]=(T[j][0],"B:application")
            T[j+1]=(T[j+1][0],"I:application")
            T[j+2]=(T[j+2][0],"I:application")
            if len(T)>j+3 and re.search(r'^[0-9.\-_]+$',T[j+3][0]):
                T[j+3]=(T[j+3][0],"B:version")
        if T[j][0].lower()=="java" and len(T)>j+3 and T[j+1][0].lower()=="system" and T[j+2][0].lower()=="web" and T[j+3][0].lower()=="server":
            T[j]=(T[j][0],"B:application")
            T[j+1]=(T[j+1][0],"I:application")
            T[j+2]=(T[j+2][0],"I:application")
            T[j+3]=(T[j+3][0],"I:application")
            if len(T)>j+4 and re.search(r'^[0-9.\-_]+$',T[j+4][0]):
                T[j+4]=(T[j+4][0],"B:version")
        if T[j][0].lower()=="java" and len(T)>j+3 and T[j+1][0].lower()=="system" and T[j+2][0].lower()=="access" and T[j+3][0].lower()=="manager":
            T[j]=(T[j][0],"B:application")
            T[j+1]=(T[j+1][0],"I:application")
            T[j+2]=(T[j+2][0],"I:application")
            T[j+3]=(T[j+3][0],"I:application")
            if len(T)>j+4 and re.search(r'^[0-9.\-_]+$',T[j+4][0]):
                T[j+4]=(T[j+4][0],"B:version")
        if T[j][0]=="JavaVM":
            T[j]=(T[j][0],"B:application")
        if len(T)>j+1 and T[j+1][1]=="B:version" and T[j][0].lower()=="java":
            T[j]=(T[j][0],"B:application")
        if T[j][0].lower()=="java" and j!=0:
            if T[j-1][1]=="B:vendor" or T[j-1][1]=="I:vendor":
                T[j]=(T[j][0],"B:application")
        if len(T)>j+1 and T[j+1][0]!="" and re.search(r'[A-Z]',T[j+1][0][0]) and T[j][0].lower()=="java":
            T[j]=(T[j][0],"B:application")
            T[j+1]=(T[j+1][0],"I:application")

        # function, methods, and parameter tagging
        if re.search(r'^[a-zA-Z0-9\_\.]*[a-z0-9]+[A-Z]+',T[j][0]) or re.search(r'^[a-zA-Z0-9\_\.]*[A-Za-z0-9\.]+\_[a-zA-Z0-9\.]+'  ,  T[j][0]):
            if len(T)>j+1:
                if re.search(r'^function', T[j+1][0]):
                    T[j]=(T[j][0],"B:function")
                    if j>1 and re.search(r'(^and$|^or$)',T[j-1][0]) and re.search(r'(^[a-zA-Z0-9\_\.]*[a-z0-9]+[A-Z]+|^[a-zA-Z0-9\_\.]*[A-Za-z0-9\.]+\_[a-zA-Z0-9\.]+)'  ,  T[j-2][0]):
                        T[j-2]=(T[j-2][0],"B:function")
            if len(T)>j+1:
                if re.search(r'^method', T[j+1][0]):
                    T[j]=(T[j][0],"B:method")
                    if j>1 and re.search(r'(^and$|^or$)',T[j-1][0]) and re.search(r'(^[a-zA-Z0-9\_\.]*[a-z0-9]+[A-Z]+|^[a-zA-Z0-9\_\.]*[A-Za-z0-9\.]+\_[a-zA-Z0-9\.]+)'  ,  T[j-2][0]):
                        T[j-2]=(T[j-2][0],"B:method")
                if re.search(r'^parameter',T[j+1][0]):
                    T[j]=(T[j][0],"B:parameter")
                    if j>1 and re.search(r'(^and$|^or$)',T[j-1][0]) and re.search(r'(^[a-zA-Z0-9\_\.]*[a-z0-9]+[A-Z]+|^[a-zA-Z0-9\_\.]*[A-Za-z0-9\.]+\_[a-zA-Z0-9\.]+)'  ,  T[j-2][0]):
                        T[j-2]=(T[j-2][0],"B:parameter")

        # file tagging
        if re.search(r'\.[a-zA-Z0-9]{1,4}$',T[j][0]):
            if j>1 and re.search(r"^function",T[j-2][0]) and T[j-1][0]=="in":
                T[j]=(T[j][0],"B:file")	
            if len(T)>j+1 and re.search(r'^file$|^files$|^script$|^scripts$',T[j+1][0]):	
                T[j]=(T[j][0],"B:file")
        if re.search(r'[a-zA-Z0-9.\-_]+/[a-zA-Z0-9.\-_]+\.[a-zA-Z0-9]{0,4}$', T[j][0]):
            T[j]=(T[j][0],"B:file")

        # component and plug-in tagger
        if re.search("component", T[j][0]) or re.search("plugin", T[j][0]) :
            k=j-1
            i=0
            while k>0:
                if re.search(r"^[A-Z]+",T[k][0])and T[k][1]=="O":
                    T[k]=(T[k][0], "I:application")
                    k=k-1
                    i+=1
                else:
                    k=-1
            if i>0:
                T[j-i]=(T[j-i][0],"B:application")

        if j>1 and re.search("plug", T[j-2][0]) and re.search("-", T[j-1][0]) and re.search("in", T[j][0]):
            k=j-1
            i=0
            while k>0:
                if re.search(r"^[A-Z]+",T[k][0])and T[k][1]=="O":
                    T[k]=(T[k][0], "I:application")
                    k=k-1
                    i+=1
                else:
                    k=-1
            if i>0:
                T[j-i]=(T[j-i][0],"B:application")


        # ad hoc tagger
        if T[j][0]=="Windows" and j>0:
            T[j]=(T[j][0], "B:os")
        if T[j][0]=="Internet" and len(T)>j+1 and T[j+1][0]=="Explorer":
            T[j]=(T[j][0], "B:application")
            T[j+1]=(T[j+1][0], "I:application")
        if T[j][0]=="Apple" and len(T)>j+1 and T[j+1][0]=="Safari":
            T[j]=(T[j][0], "B:vendor")
            T[j+1]=(T[j+1][0], "B:application")
        if re.search("Oracle", T[j][0]):
            k=j+1
            i=0
            while k<len(T):
                if re.search(r"^[A-Z]+",T[k][0]) and T[k][1]=="O":
                    T[k]=(T[k][0], "I:application")
                    k=k+1
                    i+=1
                else:
                    k=len(T)
            if i>0:
                T[j]=(T[j][0], "B:vendor")
                T[j+1]=(T[j+1][0],"B:application")
        if T[j][0]=="WebKit":
            T[j]=(T[j][0], "B:application")

        # Items I added
        if T[j][0] == "Firefox" or T[j][0] =="Chrome" or T[j][0] =="IE":
            T[j]=(T[j][0], "B:application")
            if j>0 and T[j-1][0]=="Mozilla" or T[j-1][0]=="Google" or T[j-1][0]=="Microsoft":
                T[j-1]=(T[j-1][0], "B:vendor")
                
    return T


#obj = both_tags()
#for i in range(0,len(obj)):
#    jsonify(obj[i],path2 + 'labeling_output/file' + str(i) + '.graphson')
tagged = tagged_corpus_dict()
jsonify(tagged,path2 + 'labeling_output' + '/MS_bulletin_tagged_text.graphson')
#sample2(25,path2 + 'MS_labels_sample3.txt')

