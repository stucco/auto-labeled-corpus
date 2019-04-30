# NVD_text_labeling2.py

from collections import defaultdict
import json, re, pickle, nltk
import copy
import os
import codecs
import numpy as np 

debug = True

path=os.getcwd()+"/nvdcve-2010-2013" #file extension to another folder
path_nvd_2010=path+"/nvdcve-2.0-2010.graphson" # each years' NVD node file
path_nvd_2011=path+"/nvdcve-2.0-2011.graphson"
path_nvd_2012=path+"/nvdcve-2.0-2012.graphson"
path_nvd_2013=path+"/nvdcve-2.0-2013.graphson"

path_train="/nvd_2010-2013.train.graphson" # output path, a "cveid":"tagged sentence" dictionary
path_out=path+"/nvd_2010-2013_w_tags.graphson" # output path, the same graphson file, for all 4 years w/ a new value "tagged" and the tagged text saved
path_pickle_corpus_dict=path+"/pickle_corpus_dict"

path_out_sample=path+"/random_sample" # used for validation.  Writes randomly sampled cve entries w/ tags to .txt file.  I then hand-checked these.  

path_pickle=path+"/pickle_java_words_tags.p"
path_pickleD=path+"/pickle_D"
path_pickleA=path+"/pickle_A.p"


# # take .json files into python dict
File2010=path_nvd_2010	
obj_text = codecs.open(File2010, 'r', encoding='utf-8').read()
obj2010 = json.loads(obj_text)

File2011=path_nvd_2011
obj_text = codecs.open(File2011, 'r', encoding='utf-8').read()
obj2011 = json.loads(obj_text)

File2012=path_nvd_2012
obj_text = codecs.open(File2012, 'r', encoding='utf-8').read()
obj2012 = json.loads(obj_text)

File2013=path_nvd_2013
obj_text = codecs.open(File2013, 'r', encoding='utf-8').read()
obj2013 = json.loads(obj_text)

obj={2010:obj2010, 2011:obj2011, 2012:obj2012, 2013:obj2013}

####### Make a dictionary of the corpus tagged and pos_tagged ########


def both_tags():
	"""
	returns a dictionary, called "obj", with a key for each year.  obj[year] is 
	the graphson file dictionary.  This adds a new field, "tagged_text" 
	Which is a triple, the word, the NVD-tag, and the POS-tag
	"""
	File2010=path_nvd_2010	
	obj_text = codecs.open(File2010, 'r', encoding='utf-8').read()
	obj2010 = json.loads(obj_text)

	File2011=path_nvd_2011
	obj_text = codecs.open(File2011, 'r', encoding='utf-8').read()
	obj2011 = json.loads(obj_text)

	File2012=path_nvd_2012
	obj_text = codecs.open(File2012, 'r', encoding='utf-8').read()
	obj2012 = json.loads(obj_text)

	File2013=path_nvd_2013
	obj_text = codecs.open(File2013, 'r', encoding='utf-8').read()
	obj2013 = json.loads(obj_text)

	obj={2010:obj2010, 2011:obj2011, 2012:obj2012, 2013:obj2013}

	for year in xrange(2010,2014):
		print year
		for j in xrange(len(obj[year]["vertices"])):
			print j
			V=obj[year]["vertices"][j]
			t=V["description"].split(' ')
			ID=V["_id"]
			T=basic_tagger(t,ID)
			T=secondary_tagger(T)
			S=nltk.untag(T)
			S=nltk.pos_tag(S)
			for i in range(len(T)):
				T[i]=(T[i][0], T[i][1], S[i][1])
			obj[year]["vertices"][j]["tagged_text"]=T
		print "done with year ", year
	print "Done"
	return obj


def jsonify(obj, outFile):
	json.dump(obj, codecs.open(outFile, 'w', encoding='utf-8'), separators=(',',':'), indent=4, sort_keys=True)  

#The output of "tagged_corpus_dict" is what I saved as path_train
def tagged_corpus_dict():
	"""
	Takes the dictionary output of both_tags(), and makes a returns a new dictionary named "tagged".
	Its keys are cveids and it's values are the tagged sequence (list of tripples) for that year.    
	"""	
	tagged={}
	File=path_out=path+"/nvd_2010-2013_w_tags.graphson"	
	obj_text = codecs.open(File, 'r', encoding='utf-8').read()
	obj = json.loads(obj_text)
	for year in obj.keys():
		print year
		for j in xrange(len(obj[year]["vertices"])):
			V=obj[year]["vertices"][j]
			ID=V["_id"]
			tagged[ID]=V["tagged_text"]
		print "done with ", year
	return tagged

# V=obj[2010]["vertices"][1]
# t=V["description"].split(' ')
# print t
# ID=V["_id"]
# T=basic_tagger(t,ID)
# T=secondary_tagger(T)
# print T
# S=nltk.untag(T)
# S=nltk.pos_tag(S)
# print S
# for i in range(len(T)):
# 	T[i]=(T[i][0], T[i][1], S[i][1])
# print T


######## randomly sample from list #########

def sample2(n, path_out_sample):
	"""
	Randomly samples n tagged descriptions from the initial .graphson files (nvd nodes)
	then tags their text and writes them to a .txt file w/ path "path_out_sample"
	"""

	A=[]
	File2010=path_nvd_2010	
	obj_text = codecs.open(File2010, 'r', encoding='utf-8').read()
	obj2010 = json.loads(obj_text)
	
	File2011=path_nvd_2011
	obj_text = codecs.open(File2011, 'r', encoding='utf-8').read()
	obj2011 = json.loads(obj_text)

	File2012=path_nvd_2012
	obj_text = codecs.open(File2012, 'r', encoding='utf-8').read()
	obj2012 = json.loads(obj_text)

	File2013=path_nvd_2013
	obj_text = codecs.open(File2013, 'r', encoding='utf-8').read()
	obj2013 = json.loads(obj_text)

	obj={2010:obj2010, 2011:obj2011, 2012:obj2012, 2013:obj2013}

	for j in xrange(len(obj2010["vertices"])):
		A.append((2010, j))
	for j in xrange(len(obj2011["vertices"])):
		A.append((2011, j))
	for j in xrange(len(obj2012["vertices"])):
		A.append((2012, j))
	for j in xrange(len(obj2013["vertices"])):
		A.append((2013, j))

	np.random.shuffle(A) # replaces A w/ a jumbled version
	print A[:n]
	out=open(path_out_sample, "w")

	for i in xrange(n):
		print i
		(year,j)=A[i]
		
		# tag it
		V=obj[year]["vertices"][j]
		t=V["description"].split(' ')
		ID=V["_id"]
		T=basic_tagger(t,ID)
		T=secondary_tagger(T)

		out.write(ID+" "+str(j)+"\n")

		# s=""
		for (word,tag) in T:
			# s+=" "+word+" "+tag
			out.write(word+" "+tag+"\n")
		out.write("\n")
	out.close()
	print "DONE!"


A=[(2010, 69),(2012,2947), (2012,3345),(2011,344), (2011,1641)] 

def recheck(A):
	"""
	this function was a debugging step used in writing sample2()
	"""
	File2010=path_nvd_2010	
	obj_text = codecs.open(File2010, 'r', encoding='utf-8').read()
	obj2010 = json.loads(obj_text)
	
	File2011=path_nvd_2011
	obj_text = codecs.open(File2011, 'r', encoding='utf-8').read()
	obj2011 = json.loads(obj_text)

	File2012=path_nvd_2012
	obj_text = codecs.open(File2012, 'r', encoding='utf-8').read()
	obj2012 = json.loads(obj_text)

	File2013=path_nvd_2013
	obj_text = codecs.open(File2013, 'r', encoding='utf-8').read()
	obj2013 = json.loads(obj_text)

	obj={2010:obj2010, 2011:obj2011, 2012:obj2012, 2013:obj2013}
	for i in xrange(len(A)):
		print i
		(year,j)=A[i]
		
		# tag it
		V=obj[year]["vertices"][j]
		t=V["description"].split(' ')
		ID=V["_id"]
		T=basic_tagger(t,ID)
		T=secondary_tagger(T)

		print ID+" "+str(j)

		for (word,tag) in T:
			# s+=" "+word+" "+tag
			print word+" "+tag
	print "DONE!"

# def write_corpus(path_out):
# 	"""
# 	writes the sentences to a file.  One line for each CVE-ID description
# 	I don't think I ever used this 
# 	"""
# 	out=open(path_out, "w")
	
# 	for year in xrange(2010, 2014):

# 		#load the file
# 		inFile=path+"/nvdcve-2.0-"+str(year)+".graphson"
# 		obj_text = codecs.open(inFile, 'r', encoding='utf-8').read()
# 		obj = json.loads(obj_text)

# 		for j in xrange(len(obj["vertices"])):
# 		# for j in xrange(5):
# 			print j
# 			V=obj["vertices"][j]
# 			t=V["description"].split(' ')
# 			ID=V["_id"]
# 			T=basic_tagger(t,ID)
# 			T=secondary_tagger(T)
# 			for a,b in T:
# 				out.write(a+" "+b+"\n")
# 		print "done w/ year ", year
# 	print "DONE!"
# 	out.close()
	
# def check(n,N):
# 	"""
# 	must have obj as a global variable, it's one of the NVD node .graphson files 
# 	read into python as a dictionary.  This is a debugging function, which prints 
# 	tagged output from the specified range. 
# 	"""

# 	if n<0:
# 		n=0
# 	if N>len(obj["vertices"]):
# 		N=len(obj["vertices"])
	
# 	for V in obj["vertices"][n:N]:
# 		t=V["description"].split(' ')
# 		ID=V["_id"]

# 		print "\n ID=",ID
		
# 		T=basic_tagger(t,ID)
# 		T=secondary_tagger(T)
# 		for i,s in enumerate(T):
# 			print i,s


def sanitize(t):
	"""
	 t is a list of words.  Often words will have stranded parens, eg
	 "(also" or "end)" .  This removes stranded whitespace and puntuation
	"""
	j=0
	while j < len(t):
		if t[j]!="" :
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
	year=int(ID.split("-")[1])


	t=sanitize(t)
	tt=range(len(t)) # tt will be the lowercase version of t
	for j in xrange(len(t)):
		tt[j]=t[j].lower()
	A=[e for e in obj[year]["edges"] if e["_id"].split("_to_")[0]==ID]	
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
		for  j in xrange(len(v)):
			u[j]=tuple(v[j].split("_"))
		
		#the loop below tags the sentence
		for j in xrange(2,len(u)): # u[1]=('cpe',) always, and u[2]=(x,) w/ x="/a", "/h", "/o" 	
			n=len(u[j])
			if n==1:
				for i in xrange(len(tt)):
					if tt[i]==u[j][0]:
						T[i]=(t[i], "B:"+B[j])
			if n>1:
				for i in xrange(len(tt)-n):
					if tuple(tt[i:i+n])==u[j]:
						T[i]=(t[i], "B:"+B[j])
						for k in xrange(i+1,i+n):
							T[k]=(t[k],"I:"+B[j])

	return T

def secondary_tagger(T):
	"""
	regexs for tagging
	"""
	# for version tagging regexs
	C=[r'^[0-9]+(\.|x)+[0-9a-zA-Z\-\.]{1,}$' ,r'^[0-9.x]{2,}\.+-[0-9a-zA-Z.]+$',r'^[0-9\.x]+\.?[a-zA-Z.]+$',r'^[0-9\.x]+_[a-zA-Z0-9.]+$',r'^[0-9\.x]+\%[0-9a-zA-Z.]+$',r'^[0-9\.x]+-([0-9.]+[a-zA-Z0-9.\-_]*|[a-zA-Z0-9.\-_]*[0-9.]+)$']
	
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
			if j>0 and re.search(r'[0-9x\.\-]',T[j][0] ):
				if T[j-1][0]=="before" or T[j-1][0]=="through":
					if j>1 and re.search("version", T[j-2][1]):
						T[j-1]=(T[j-1][0],"I:version")
						T[j]=(T[j][0], "I:version")
					else: 
						T[j-1]=(T[j-1][0],"B:version")
						T[j]=(T[j][0], "I:version")
				if re.search("application", T[j-1][1]):
						T[j]=(T[j][0], "B:version")
			if len(T)>j+1 and re.search(r'[0-9x\.\-]',T[j][0] ):
				if T[j+1][0]=="and" and T[j+2][0]=="earlier":
					T[j]=(T[j][0], "B:version")
					T[j+1]=(T[j+1][0],"I:version")
					T[j+2]=(T[j+2][0], "I:version")

			if re.search("version", T[j][1]) and len(T)>j+2 and re.search(r'^[,]{1}$|^and$',T[j+1][0]) and re.search(r'^[0-9]',T[j+2][0]):
				T[j+2]=(T[j+2][0],"B:version")
			if re.search("version", T[j][1]) and len(T)>j+3 and T[j+1][0]=="," and T[j+2][0]=="and" and re.search(r'^[0-9]',T[j+3][0]):
				T[j+3]=(T[j+3][0],"B:version")		

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
		if re.search(r"^pre[0-9a-zA-Z._-]+",T[j][0]) and T[j][1]=="O":
			T[j]=(T[j][0],'B:update')
		if re.search(r"^release[_\-a-zA-Z0-9]+",T[j][0]) and T[j][1]=="O":
			T[j]=(T[j][0],'B:update')	
		if re.search(r"^update[_\-a-zA-Z0-9]+",T[j][0]) and T[j][1]=="O":
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
		# if T[j][0]=="JavaScript":
			# T[j]=(T[j][0],"B:programming language")
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
	return T

######## everything below was I think abandonded and not implemented #########

# def tagged_corpus_dict():
# 	"""
# 	returns a dictionary, with a key for each year.  The value
# 	for a given year is a list of tuples.  The tuple is of the form 
# 	(j, CVE-ID, Tagged text). j is the number this CVE-ID appears in 
# 	the graphson file list. 
# 	"""
# 	corpus=defaultdict(list)
	
# 	for year in xrange(2010, 2014):
# 		print "started " , year
# 		#load the file
# 		inFile=path+"/nvdcve-2.0-"+str(year)+".graphson"
# 		obj_text = codecs.open(inFile, 'r', encoding='utf-8').read()
# 		obj = json.loads(obj_text)
		
# 		for j in xrange(len(obj["vertices"])):
# 			V=obj["vertices"][j]
# 			t=V["description"].split(' ')
# 			ID=V["_id"]
# 			T=basic_tagger(t,ID)
# 			T=secondary_tagger(T)
# 			corpus[year].append((j,ID, T))
# 		print "done w/ year ", year		
# 	corpus=dict(corpus)
# 	pickle_file=open(path_pickle_corpus_dict, "wb")
# 	pickle.dump(corpus_dict , pickle_file)
# 	pickle_file.close()
# 	print "done"

# ## corpus_dict=tagged_corpus_list()
# pickle_file=open(path_pickle_corpus_dict, "wb")
# pickle.dump(corpus_dict , pickle_file)
# pickle_file.close()

# ##read corpus_dict from pickled file
# pickle_file = open(path_pickle_corpus_dict, 'rb')
# corpus_dict= pickle.load(pickle_file)
# pickle_file.close()


 
# def samples(n, corpus_dict, path_out_sample):
# 	A=[] # dictionary of tuples giving the index (year, number) of each entry
# 	L=[] # the list of randomly sampled items to be populated and returned
# 	c=0
# 	for year in corpus_dict.keys():
# 		for (a,b,c)in corpus_dict[year]:
# 			A.append((year, a))
	
# 	np.random.shuffle(A) # replaces A w/ a jumbled version
	
# 	# Now write the text to file:
# 	out=open(path_out_sample, "w")
# 	for i in xrange(n):
# 		(year,j)=A[i]
# 		(j,ID, T)=corpus[year][j]
# 		s=""
# 		for (word,tag) in T:
# 			s+=" "+a+" "+b

# 		out.write(str(j)+"|"+ "ID"+ "|"+ s+"\n")
# 	out.close()
	



# ##### check to see that the edges are made appropriately: #######
# def no_edge_nodes(year):
# 	edge_ids=set()

# 	# open file
# 	inFile=path+"/nvdcve-2.0-"+str(year)+".graphson"
# 	obj_text = codecs.open(inFile, 'r', encoding='utf-8').read()
# 	obj = json.loads(obj_text)
	
# 	# populate edge_ids
# 	for j in xrange(len(obj["edges"])):
# 		edge_ids=edge_ids.union(set([obj["edges"][j]["_inV"]]))	
# 		# if j%100==0:
# 		# 	print j
# 	print "done with edge_ids"		
	

# 	node_ids=set()
# 	# populate node_ids	
# 	for j in xrange(len(obj['vertices'])):
# 		node_ids=node_ids.union( set([obj["vertices"][j]["_id"]]))
		
# 	# return set difference
# 	return 	node_ids.difference(edge_ids)	
