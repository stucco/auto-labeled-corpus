#########   General functions   ###########
""" Includes functions for serialization (jsonify, unjsonify, picklify, unpickle) and accuracy_scores which computes precision,recall accuracy."""

from operator import eq
import json, pickle, codecs

# precision, recall, accuracy function
def accuracy_scores(test_sentences, tagged_sentences, save_path=None):
	"""This function returns precision, recall, f-score, accuracy (in that order)"""

	# initializing counts
	guess_not_O=0
	guess_correct=0
	guess_not_O_and_correct=0
	tag_not_O=0
	total=0
	for i in xrange(len(test_sentences)):
		# words=test_sentences[i][0] # a list of words giving the sentence
		correct_tags=test_sentences[i][-1] # a list of the corresponding correct tags
		guess_tags=tagged_sentences[i][-1] # a list of the corresponding guessed tags
		l=len(correct_tags)
		guess_not_O+=len([i for i in xrange(l) if guess_tags[i]!="O"])
		guess_correct+=len([i for i in xrange(l) if guess_tags[i]==correct_tags[i]])
		guess_not_O_and_correct +=len([i for i in xrange(l) if guess_tags[i]!="O" and guess_tags[i]==correct_tags[i]])
		tag_not_O += len([i for i in xrange(l) if correct_tags[i]!="O" ])
		total += l

	print "guess_not_O = %s, \n guess_correct = %s, \n guess_not_O_and_correct = %s, \n tag_not_O = %s, \n total = %s, \n " %(guess_not_O, guess_correct, guess_not_O_and_correct, tag_not_O, total)

	precision= float(guess_not_O_and_correct)/guess_not_O
	recall =  float(guess_not_O_and_correct)/tag_not_O
	f_score   = 2/float((1 / precision) + (1 / recall))
	accuracy = float(guess_correct)/ total

	print "precision = %s \n recall = %s \n f_score = %s \n accuracy = %s \n" %(precision, recall, f_score, accuracy)
	if save_path: 
		jsonify({"percision": precision, "recall": recall, "f_score": f_score, "accuracy": accuracy}, save_path)

	return precision, recall, f_score, accuracy


# functions for saving/opening objects
def jsonify(obj, out_file):
	"""
	Inputs:
	- obj: the object to be jsonified
	- out_file: the file path where obj will be saved
	This function saves obj to the path out_file as a json file.
	"""
	json.dump(obj, codecs.open(out_file, 'w', encoding='utf-8'), separators=(',', ':'), sort_keys=True, indent=4)

def unjsonify(in_file):	
	"""
	Input:
	-in_file: the file path where the object you want to read in is stored
	Output:
	-obj: the object you want to read in
	"""
	obj_text = codecs.open(in_file, 'r', encoding='utf-8').read()
	obj = json.loads(obj_text)
	return obj
def picklify(obj, filepath):
	"""
	Inputs:
	- obj: the object to be pickled
	- filepath: the file path where obj will be saved
	This function pickles obj to the path filepath.
	"""
	pickle_file = open(filepath, "wb")
	pickle.dump(obj , pickle_file)
	pickle_file.close()
	print "picklify done"
def unpickle(filepath):
	"""
	Input:
	-filepath: the file path where the pickled object you want to read in is stored
	Output:
	-obj: the object you want to read in
	"""
	pickle_file = open(filepath, 'rb')
	obj = pickle.load(pickle_file)
	pickle_file.close()
	return ob
