# main.py

# file to run 
from collections import defaultdict
from generalFunctions import * # jsonify and pickling functions
import re, pickle, os, random, copy, time
import AveragedPerceptronIOB as apIOB
import AveragedPerceptronNVD as apNVD

####### Paths ########
path= os.getcwd()
# path to whole data set
# path1=os.path.abspath(os.path.join(path,"..")) # go up a directory
path_train=os.path.join(os.path.join(path, "training_data") , "new_nvd_training.json") # labeled corpus from NVD tagging
print os.path.isfile(path_train) #checks to make sure it's truely a path to a file
# path to save objects and results from testing
path_results=os.path.join(path, "ap_tests_and_results")
if not os.path.exists(path_results):
	os.makedirs(path_results)

######## Test-Run functions: functions that run the perceptron code, calculates results, and save it #########
def IOB_test_run(n, path_train=path_train, save_path=None):
	print "Begin IOB-run with n = %d" % int(n)
	## setting up .8n training sentences & .2n test sentences
	n=int(n)
	train=unjsonify(path_train)
	random.shuffle(train)
	train=train[:n]
	# Throw out the nvd_tags
	training=[(words, pos_tags, iob_tags) for (words, pos_tags,iob_tags,nvd_tags) in train]
	sentences=training[:int(.8*n)]	
	test_sentences=training[int(.8*n):]
	print "Randomly chosen %d training sentences & %d test sentences" %(len(sentences), len(test_sentences))

	if save_path:
		## This checks to see if there's already been a test run w/ this size data.  If not
		## it makes a new folder for the data and results. 
		## If so, it makes a new folder for the data and the results, incrementing the folder
		## name by 1. 
		path2=os.path.join(save_path,"ap_instances_IOB_w_pos")
		path=os.path.join(save_path, "IOB_data_size_"+str(n))
		c=1
		path=path+"_"+str(c)
		while os.path.exists(path): 
			c+=1
			path=path[:-2]+"_"+str(c)			
		if not os.path.exists(path):
			os.makedirs(path)
		print "Results will be saved in %s" %path

		# Initiate the AveragedPerceptron Instance
		start=time.clock()
		A=apIOB.AveragedPerceptronIOB(sentences)
		AP_init_time=time.clock()-start #setup time
		print "The number of features = %d" % len(A.weights.keys())
		print "The tags are %s" % A.tags
		print "Now we'll train..."

		# Training
		start=time.clock()
		A.train(verbose=True, save_path=os.path.join(path2,"IOB_data_size_"+str(n)))
		AP_train_time=time.clock()-start #training time

		# Tag the test set and compute accuracy results
		start=time.clock()
		A.test_accuracy(test_sentences, save_path=os.path.join(path,'IOBresults'))
		AP_tagging_and_computing_results_time=time.clock()-start

		# timing results
		print "APIOB_init_time = %f, APIOB_train_time = %f, APIOB_tagging_and_computing_results_time = %f" %(AP_init_time, AP_train_time, AP_tagging_and_computing_results_time)
		jsonify( {"APIOB_init_time":AP_init_time, "APIOB_train_time":AP_train_time, "APIOB_tagging_and_computing_results_time":AP_tagging_and_computing_results_time}, os.path.join(path, "_time"))

	else: # case when save_path not given

		start=time.clock()
		A=apIOB.AveragedPerceptronIOB(sentences)
		AP_init_time=time.clock()-start #setup time

		print "The number of features = %d" % len(A.weights.keys())
		print "The tags are %s" % A.tags
		print "Now we'll train..."
		
		start=time.clock()
		A.train(verbose=True)
		AP_train_time=time.clock()-start #training time

		start=time.clock()
		A.test_accuracy(test_sentences)
		AP_tagging_and_computing_results_time=time.clock()-start

		print "APIOB_init_time = %f, APIOB_train_time = %f, APIOB_tagging_and_computing_results_time = %f" %(AP_init_time, AP_train_time, AP_tagging_and_computing_results_time)
	
def NVD_test_run(n, path_train=path_train, save_path=None):
	"""IOB tags are ground truth, given.  This uses them to see how it does for just the nvd_tags"""
	
	print "Begin NVD (only) run with n = %d" % int(n)
	## setting up .8n training sentences & .2n test sentences
	n=int(n)
	train=unjsonify(path_train)
	random.shuffle(train)
	train=train[:n]
	sentences=train[:int(.8*n)]	
	test_sentences=train[int(.8*n):]
	print "Randomly chosen %d training sentences & %d test sentences" %(len(sentences), len(test_sentences))

	if save_path:
		## This checks to see if there's already been a test run w/ this size data.  If not
		## it makes a new folder for the data and results. 
		## If so, it makes a new folder for the data and the results, incrementing the folder
		## name by 1. 
		path2=os.path.join(save_path,"ap_instances_NVD_w_pos")
		path=os.path.join(save_path, "NVD_data_size_"+str(n))
		c=1
		path=path+"_"+str(c)
		while os.path.exists(path): 
			c+=1
			path=path[:-2]+"_"+str(c)			
		if not os.path.exists(path):
			os.makedirs(path)
		print "Results will be saved in %s" %path

		# Initiate the AveragedPerceptron Instance
		start=time.clock()
		A=apNVD.AveragedPerceptronNVD(sentences)
		AP_init_time=time.clock()-start #setup time
		print "The number of features = %d" % len(A.weights.keys())
		print "The tags are %s" % A.tags
		print "Now we'll train..."

		# Training
		start=time.clock()
		A.train(verbose=True, save_path=os.path.join(path2,"NVD_data_size_"+str(n)))
		AP_train_time=time.clock()-start #training time

		# Tag the test set and compute accuracy results
		start=time.clock()
		A.test_accuracy(test_sentences, save_path=os.path.join(path,'NVDresults'))
		AP_tagging_and_computing_results_time=time.clock()-start

		# timing results
		print "APNVD_init_time = %f, APNVD_train_time = %f, APNVD_tagging_and_computing_results_time = %f" %(AP_init_time, AP_train_time, AP_tagging_and_computing_results_time)
		jsonify( {"APNVD_init_time":AP_init_time, "APNVD_train_time":AP_train_time, "APNVD_tagging_and_computing_results_time":AP_tagging_and_computing_results_time}, os.path.join(path, "_time"))

	else: # case when save_path not given

		start=time.clock()
		A=apNVD.AveragedPerceptronNVD(sentences)
		AP_init_time=time.clock()-start #setup time

		print "The number of features = %d" % len(A.weights.keys())
		print "The tags are %s" % A.tags
		print "Now we'll train..."
		
		start=time.clock()
		A.train(verbose=True)
		AP_train_time=time.clock()-start #training time

		start=time.clock()
		A.test_accuracy(test_sentences)
		AP_tagging_and_computing_results_time=time.clock()-start

		print "APNVD_init_time = %f, APNVD_train_time = %f, APNVD_tagging_and_computing_results_time = %f" %(AP_init_time, AP_train_time, AP_tagging_and_computing_results_time)


# IOB_test_run(100, save_path=path_results+"_IOB_no_pos")
# IOB_test_run(100, save_path=path_results+"_IOB_no_pos")
# IOB_test_run(100, save_path=path_results+"_IOB_no_pos")
# IOB_test_run(100, save_path=path_results+"_IOB_no_pos")
# IOB_test_run(100, save_path=path_results+"_IOB_no_pos")

# IOB_test_run(500, save_path=path_results+"_IOB_no_pos")
# IOB_test_run(500, save_path=path_results+"_IOB_no_pos")
# IOB_test_run(500, save_path=path_results+"_IOB_no_pos")
# IOB_test_run(500, save_path=path_results+"_IOB_no_pos")
# IOB_test_run(500, save_path=path_results+"_IOB_no_pos")

# IOB_test_run(1000, save_path=path_results+"_IOB_no_pos")
# IOB_test_run(1000, save_path=path_results+"_IOB_no_pos")
# IOB_test_run(1000, save_path=path_results+"_IOB_no_pos")
# IOB_test_run(1000, save_path=path_results+"_IOB_no_pos")
# IOB_test_run(1000, save_path=path_results+"_IOB_no_pos")

# IOB_test_run(15000, save_path=path_results+"_IOB_w_pos")
# IOB_test_run(15000, save_path=path_results+"_IOB_w_pos")
# IOB_test_run(15000, save_path=path_results+"_IOB_w_pos")
# IOB_test_run(15000, save_path=path_results+"_IOB_w_pos")
# IOB_test_run(15000, save_path=path_results+"_IOB_w_pos")

# save_path=path_results+"_NVD_w_pos"
# print "%s is dir? %s" %(save_path, os.path.isdir(save_path))

# NVD_test_run(15000, save_path=path_results+"_NVD_w_pos")
# NVD_test_run(15000, save_path=path_results+"_NVD_w_pos")
# NVD_test_run(15000, save_path=path_results+"_NVD_w_pos")
# NVD_test_run(15000, save_path=path_results+"_NVD_w_pos")
# NVD_test_run(15000, save_path=path_results+"_NVD_w_pos")

# NVD_test_run(500, save_path=path_results+"_NVD_no_pos")
# NVD_test_run(500, save_path=path_results+"_NVD_no_pos")
# NVD_test_run(500, save_path=path_results+"_NVD_no_pos")
# NVD_test_run(500, save_path=path_results+"_NVD_no_pos")
# NVD_test_run(500, save_path=path_results+"_NVD_no_pos")

# NVD_test_run(1000, save_path=path_results+"_NVD_no_pos")
# NVD_test_run(1000, save_path=path_results+"_NVD_no_pos")
# NVD_test_run(1000, save_path=path_results+"_NVD_no_pos")
# NVD_test_run(1000, save_path=path_results+"_NVD_no_pos")
# NVD_test_run(1000, save_path=path_results+"_NVD_no_pos")

# NVD_test_run(2500, save_path=path_results+"_NVD_no_pos")
# NVD_test_run(2500, save_path=path_results+"_NVD_no_pos")
# NVD_test_run(2500, save_path=path_results+"_NVD_no_pos")
# NVD_test_run(2500, save_path=path_results+"_NVD_no_pos")
# NVD_test_run(2500, save_path=path_results+"_NVD_no_pos")



