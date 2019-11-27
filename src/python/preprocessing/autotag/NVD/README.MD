Documentation of the "auto-tagging" of NVD text descriptions

We already have the NVD entries from 2010 - present in the graph, so I used the .graphson files in nvdcve-2010-2013 which encodes the NVD nodes and their edges to CPE nodes.  The NVD_text_labeling2.py script does the following:

* 0. The script reads in the CVE id and the associated text.
* 1. It normalizes the text:
	-makes it a list of strings (words)
	-omits unnecessary white space
	-separates punctuation as individual words
* 2. It uses the CVE id to look up any edges from that id to a CPE node.
* 3.  Basic tagger: now it takes the entities from the CPE node (software vendor, version, …) and searches the text string, tagging them appropriately.
* 4. 2ndary tagger: A list of regular expressions which performs tagging.  This includes things like regexs for version based on wording, numbers, and punctuation, regexs for functions using camel/snake case.
* 5.  There is also a "relevant terms" tagger which tags termed frequently used as indicators of the weakness involved, for example  "SQL injection", "XSS", "remote code execution".  This is a dictionary look up and w/ about 50 terms which were decided upon by sorting the NVD entries by CWE classification, then manually inspecting the most frequent uni-, bi-, trigrams.  
  * 5.1 I think w/ a ML algorithm for associated a CWE tag to a text description of a vulnerability is possible with decent results.  
* 6. The sentences are then part of speech tagged using NLTK's out of the box tagger.
* 7.   The output is a dictionary (python) saved as a .json file.  For each CVE id  the text description is given, now w/ 2 tags- the NVD tags (vendor, version, application, function, parameter, relevant term), and the POS tag.
  * 7.1 IOB tagging is also used to understand entities w/ more than one word
