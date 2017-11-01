# averaged_perceptronNVD
# the original averaged perceptron configured here for NVD tagging 
# takes pos and iob tags as input for features

from collections import defaultdict
import json, re, pickle, os, random, copy, codecs
from generalFunctions import *  # jsonify and pickling functions

class AveragedPerceptronNVD(object):
	'''An averaged perceptron, similar to one by Matthew Honnibal.

	See his implementation details here:
		http://honnibal.wordpress.com/2013/09/11/a-good-part-of-speechpos-tagger-in-about-200-lines-of-python/
	'''

	def _get_features(self, i, context, pos_context, iob_context, prev, prev2):
		'''Map tokens-in-contexts into a feature representation, returns features as a
		set. If the features change, a new model must be trained. i is the index of the word
		in the sentence, context is a dictionary of the words in the sentence plus _START_ and _END_
		with keys -2 to l+1. pos is the list of pos tags in the sentence  
		prev2 , prev are the previous 2 tags'''
		
		word=context[i] # current word		
		
		def add(name, *args): # an internal function for making/adding feature names to the set
			features.add('+'.join((name,) + tuple(args)))

		features = set()
		
		## prefix/ suffix features below
		# add('bias') # This acts sort of like a prior
		# add('i suffix', word[-3:])
		# add('i pref1', word[0])
		# add('i-1 suffix', context[i-1][-3:])
		# add('i+1 suffix', context[i+1][-3:])
		
		## tag and word features below:
		add('i-1 tag', prev)
		add('i-2 tag', prev2)
		add('i-1 tag + i-2 tag', prev, prev2)
		add('i word', context[i])
		add('i-1 tag + i word', prev, context[i])
		add('i-1 word', context[i-1])
		add('i-2 word', context[i-2])
		add('i+1 word', context[i+1])
		add('i+2 word', context[i+2])
		add('i-1 pos', pos_context[i-1])
		add('i-2 pos', pos_context[i-2])
		add('i-1 pos + i word', pos_context[i-1], context[i])
		add('i+1 pos', pos_context[i+1])
		add('i-1 iob', iob_context[i-1])
		add('i-2 iob', iob_context[i-2])
		add('i-1 iob + i word', iob_context[i-1], context[i])
		add('i+1 iob', iob_context[i+1])

		# Gazetteer Features
		if context[i] in self.gazetteer["vendor"]:
			add('vendor gazetteer')
		if context[i] in self.gazetteer["product"]:
			add("product gazetteer")
		## regex features below
		R=[(r"^[A-Z]{1}","FirstCap"),(r"[a-z0-9]{1,}[A-Z]{1,}","InteriorCap"),(r"^[0-9]","First#"),(r".*[0-9]", "Interior#"),(r"[.,\?/\-\[\]\'\":;!@]","Punctuation"),(r"[a-zA-Z0-9]{1,}_","Underscore"), (r"^\(", "LeftParen"), (r"\)$","RightParen")]
		for regex,name in R:
			if re.search(regex,word):
				add('i '+name,)
			if re.search(regex,context[i-1]):
				add('i-1 '+name,)
			if re.search(regex,context[i-2]):
				add('i-2 '+name,)
			if re.search(regex,context[i+1]):
				add('i+1 '+name,)
			if re.search(regex,context[i+2]):
				add('i+2 '+name,)
		
		return features

	def __init__(self, sentences, verbose=True):
		"""sentences is a list of quadruples of the form (words, pos_tags, iob_tags, nvd_tags).  
			words, pos_tags, iob_tags, nvd_tags are all lists.  This is the labeled-data input."""

		if verbose:
			print "AveragedPerceptronNVD initialization begun. \nInitiating tags..."

		# classes will be the possible tags
		self.tags=set()
		
		self.gazetteer={"vendor": set(), "product":set()} #initiating 2 gazetteers to be populated now, and used for features
		# populate tags set & gazetteer
		for words, pos_tags,iob_tags, nvd_tags in sentences:
			for i,t in enumerate(nvd_tags):
				self.tags=self.tags.union(set([t]))
				
				if t=="sw.vendor":
					self.gazetteer["vendor"].add(words[i])
				elif t=="sw.product":
					self.gazetteer["product"].add(words[i])

		if verbose:
			print "Initiating tagdict..."
		# since many words will be used with only 1 tag, we make a dictionary
		# of these unambiguous terms so they can be auto-labeled
		self.tagdict={}

		# populate the tagdict
		pre_tagdict=defaultdict(set)
		for words, pos_tags, iob_tags, nvd_tags in sentences:
			for j in xrange(len(words)):
				w=words[j]
				t=nvd_tags[j]
				pre_tagdict[w] = pre_tagdict[w].union(set([t])) # a bug? chenged the code according to the descriptions above
		self.tagdict={x:list(y)[0] for x,y in pre_tagdict.items() if len(y)==1}

		if verbose:
			print "Generating features and intitiating all weights to 0..."

		# We want a weight for each (feature, tag) pair so 
		# weights will be a dictionary of dictionaries. 
		# weights[feature name][tag name]= float
		# note that weights.keys() gives our list of features
		self.weights={}
		# initialize the weights to 0
		features=set()
		for words, pos_tags, iob_tags, nvd_tags  in sentences:
			# make context dicts for the sentence
			l=len(words)
			context={-2:"_START_",-1:"_START_", l:"_END_", l+1:"_END_"}
			pos_context={-2:"_PSTART_",-1:"_PSTART_", l:"_PEND_", l+1:"_PEND_"}
			iob_context={-2:"_ISTART_",-1:"_ISTART_", l:"_IEND_", l+1:"_IEND_"}
			for i,word in enumerate(words):
				context[i]=word			
				pos_context[i]=pos_tags[i]
				iob_context[i]=iob_tags[i]

			# get features observed in this sentence
			prev2="n_START_"
			prev="n_START_"
			for i,word in enumerate(words):
				features=features.union(self._get_features(i,context,pos_context, iob_context, prev,prev2))
				prev2=prev
				prev=nvd_tags[i]
		for f in features:
			self.weights[f]={}
			for c in self.tags:
				self.weights[f][c]=0


		# for averaging we need to accumulated values for each 
		# (feature, tag) pair (keys here are the tuples (f,t))
		# these are the numerator
		self._totals=defaultdict(int)

		# we will also need a timestamp to tell us when the 
		# last time a weight was changed.  again keys are (f,t)
		self._tstamps=defaultdict(int)

		self.i=.000001 	# a counter for how many training examples we've used thus far.  
						# We initiate it to a small number to avoid div by 0 error. 
		
		self.sentences=sentences #make the training data an attribute
		if verbose:
			print "Done with Averaged Perceptron __init__. \n  Let's do this!"

	def predict(self, features):
		"""Returns the best tag for a word.  features is the set of features that fired for a word we want to tag"""
		scores=defaultdict(float) # to be populated and used to return the best tag
		for feat in features:
			if feat not in self.weights:
				continue
			weights=self.weights[feat] # just the dictionary for this feature name.  It has a key for each possible label.  
			for label, weight in weights.items():
				scores[label]+= weight
		return max(self.tags, key=lambda label: (scores[label], label))

	def update(self, features, true_tag, guess): # (features, true_tag) is a training example, guess = self.predict(features)
		self.i += 1 # update the counter

		for f in self.weights.keys():
			if f in features:
				if true_tag!=guess:	
					self._totals[(f,true_tag)]+= (self.i - self._tstamps[(f,true_tag)])*self.weights[f][true_tag]
					self.weights[f][true_tag]+=1
					self._tstamps[(f,true_tag)]=self.i
					# the above three lines do the updating for the true_tag label
					self._totals[(f,guess)]+=(self.i - self._tstamps[(f,guess)])*self.weights[f][guess]
					self.weights[f][guess]-=1
					self._tstamps[(f,guess)]=self.i # this line should be another bug ,too. this line should update the _tstamps of weight[f][guess].
				
	def average_weights(self):
		"""after all iterations, we create the trained weights by averaging the totals"""
		for feat, old_weights in self.weights.items(): # note: old_weights is a dictionary of the form tag:value
			new_weights={}
			for tag, weight in old_weights.items():
				# we need to get the last timesteps added to the totals 
				final_total=self._totals[(feat,tag)]+((self.i-self._tstamps[(feat,tag)])*weight)
				new_weights[tag]=float(final_total)/float(self.i)
			self.weights[feat]=new_weights

	def train(self, save_path=None, num_it=5, verbose=False):
		"""Trains the parameters (learns the weights) using averaged perceptron, and saves items
		in save_path if given.  Number of iterations through the training set is num_it. """

		for iter in xrange(num_it):
			random.shuffle(self.sentences)
			if verbose:
				print "Train: Beginning iteration %d" % iter
			c=0 # counts the number of correct guesses
			n=0 # number of guesses 
			for words, pos_tags, iob_tags, nvd_tags  in self.sentences:
				# setup for this sentence includes start tags and making context
				prev, prev2="n_START_", "n_START_" 
				# make context for the sentence
				l=len(words)
				context={-2:"_START_",-1:"_START_", l:"_END_", l+1:"_END_"}
				pos_context={-2:"_PSTART_",-1:"_PSTART_", l:"_PEND_", l+1:"_PEND_"}
				iob_context={-2:"_ISTART_",-1:"_ISTART_", l:"_IEND_", l+1:"_IEND_"}
				for i,word in enumerate(words):
					context[i]=word			
					pos_context[i]=pos_tags[i]
					iob_context[i]=iob_tags[i]

				# guess and update
				for i,word in enumerate(words):	
					guess=self.tagdict.get(word) # if it's a nonambiguous word, it's autolabeled and we don't update
					if not guess:
						features=self._get_features(i, context ,pos_context,iob_context, prev, prev2)
						guess=self.predict(features)
						self.update(features, nvd_tags[i], guess) # we only update if we used the predictor 
					prev2=prev
					prev=guess
					#update the counts
					if guess==nvd_tags[i]:
						c+=1
					n+=1
			if verbose:
				print "Train: Finished iteration %d: Accuracy %d/%d" %(iter, c, n)
			
		# replace weights with average weights now
		self.average_weights()
		# save the whole class now that it's trained
		if save_path:
			picklify(self, save_path)


	def tag_new_sentences(self, new_sentences, verbose=True):
		""" 
		new_sentences is a list of triples (words, pos_tags, iob_tags), and this produces & returns the list of quadruples
		(words, pos_tags, iob_tags, new_tags) using the weights dictionary
		""" 
		if verbose:
			print "Tagging sentences..."
		length=len(new_sentences)# for verbose=True printouts
		c=0 # counter for verbose=True printouts

		tagged_sentences=[] # to be populated and returned
		for words, pos_tags, iob_tags in new_sentences:
			new_tags=[]# list of tags for the sentence to be populated 
			## setup for this sentence includes start tags and making context
			prev, prev2="n_START_", "n_START_" 
			# make context for the sentence
			l=len(words)
			context={-2:"_START_",-1:"_START_", l:"_END_", l+1:"_END_"}
			pos_context={-2:"_PSTART_",-1:"_PSTART_", l:"_PEND_", l+1:"_PEND_"}
			iob_context={-2:"_ISTART_",-1:"_ISTART_", l:"_IEND_", l+1:"_IEND_"}
			for i,word in enumerate(words):
				context[i]=word			
				pos_context[i]=pos_tags[i]
				iob_context[i]=iob_tags[i]

			# guess the tags
			for i,word in enumerate(words):	
				guess=self.tagdict.get(word) # if it's a nonambiguous word, it's autolabeled
				if not guess:
					features=self._get_features(i, context, pos_context, iob_context, prev, prev2)
					guess=self.predict(features)
				new_tags.append(guess)
				prev2=prev
				prev=guess
			tagged_sentences.append((words, pos_tags, iob_tags, new_tags))
			
			c+=1 # update counter for verbose=True printouts 
			if c%250==0:
				print "%d of %d sentences tagged." % (c,length)
		return tagged_sentences

	def test_accuracy(self, test_sentences,  verbose=True, save_path=None):
		""" 
		guesses tags for the test set, then computes precision, recall, f_score, and accuracy scores
		""" 
		new_sentences=[(words, pos_tags, iob_tags) for (words, pos_tags, iob_tags, nvd_tags) in test_sentences]
		tagged_sentences=self.tag_new_sentences(new_sentences, verbose=verbose)
		# print "tagged_sentences = ", tagged_sentences
		# print "test_sentences = ", test_sentences
		precision, recall, f_score, accuracy=accuracy_scores(test_sentences, tagged_sentences, save_path=save_path)
		return precision, recall, f_score, accuracy



