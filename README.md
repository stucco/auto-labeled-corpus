auto-labeled-corpus
===================

This is a corpus of auto-labeled cyber security domain text.

This was generated for use in the [Stucco project,](http://stucco.github.io/) but we hope this corpus will be useful to many others in the field.

This includes all descriptions from CVE/NVD entries starting in 2010.  
Note that MS Bulletins are named with their CVE number, specified in the vuln:CVE field.

****

This corpus was generated and first used in the following paper, which provides many additional details.  If this work or this corpus is useful in your research, please include this citation.

Bridges, Robert A., et al. "Automatic Labeling for Entity Extraction in Cyber Security.” accepted The Third ASE International Conference on  Cyber Security 2014. Preprint arXiv preprint arXiv:1308.4941 (2013).

****



# Generating Tagged Corpus

The `src/python/tagging` directory contains scripts to generate and tag the initial corpus, using various heuristics.

#### Input
The *_preprocess.py files will fetch the source data and perform any needed pre-processing to generate the un-labeled corpus (in json format.)

#### Process
For each source, run the appropriate *_preprocess.py script, followed by the matching *_tagging.py script.

#### Output
Each source will generate a *_corpus.json file, which corresponds to the files in the `corpus` directory




# Generating (and Evaluating) Models from Corpus

The `src/python/learning` directory contains scripts to generate a model from the tagged corpus, and then evaluate this model.

This implementation is using [Apache OpenNLP](https://opennlp.apache.org)

## Training
Training is done for IOB-tagging, and then domain labeling, but the process is the same for both.

#### Input
The nvd_corpus.json file is used as input.

#### Process

1) The nvd_corpus.json file is converted into an event stream file, where an event consists of a target IOB tag, or domain label, followed by space-delimited context values (i.e. features). The file contains one event per line. Two files will be created, one for training in IOB-tagging, and the other for training in domain labeling.

Here is an example of a small snippet from the nvd_corpus.json:

	"CVE-2012-0478":[
            ...
            [
                 "subsystem",
                 "O"
            ],
            [
                "in",
                "O"
            ],
            [
                "Mozilla",
                "B-vendor"
            ],
            [
                "Firefox",
                "B-application"
            ],
            [
                "4.x",
                "B-version"
            ],
            [
                "through",
                "I-version"
            ],
            [
                "11.0",
                "I-version"
            ],
            ...


Below is a few of the corresponding domain-labeling events:

	sw.vendor O O O__O O O B B B Mozilla O__Mozilla O__Mozilla subsystem in Firefox 4.x NN IN NNP NNP CD
	sw.product O sw.vendor O__sw.vendor O B B B I Firefox sw.vendor__Firefox B__Firefox in Mozilla 4.x through IN NNP NNP CD IN
	sw.version sw.vendor sw.product sw.vendor__sw.product B B B I I 4.x sw.product__4.x B__4.x Mozilla Firefox through 11.0 NNP NNP CD IN CD

2) Next, one of the event stream files is used by the opennlp.perceptron.PerceptronTrainer.

Here is a snippet of the code used to train the averaged perceptron:

	/** 
	 * Open an event stream file, where the format of the file is one event per line
	 * And, an event consists of a target label followed by space-delimited context values (i.e. features)
	 */
	EventStream events = new FileEventStream(new File(eventFileName));

	/** 
	 * TwoPassDataIndexer(EventStream eventStream, int cutoff, boolean sort)
	 *		eventStream - sequence of events to train with
	 *		cutoff - minimum number of times a context value must be seen to be included in the model
	 *		sort - true, if the final model should be filtered to contain only the unique events; false, otherwise
	 */
	DataIndexer dataIndexer = new TwoPassDataIndexer(events, 1, false);

	/**
	 *  trainModel(int iterations, DataIndexer dataIndexer, int cutoff, boolean useAverage)
	 *  	iterations - number of runs through the data that should be made to train the model
	 *  	dataIndexer - object that collects the context and counts the number of occurrences for each context value
	 *  	cutoff - not actually used in the PerceptronTrainer object; only in the SimplePerceptronSequenceTrainer
	 *  	useAverage - true, to use averaged perceptron training; false, otherwise
	 */
	model = (PerceptronModel) trainer.trainModel(100, dataIndexer, 0, true);


#### Output
Two opennlp.perceptron.PerceptronModel objects are produced, namely, the IOB-tagging model and the domain labeling model.

## Testing
Testing is done for IOB-tagging, and then domain labeling, but the process is the same for both.

#### Input
The two opennlp.perceptron.PerceptronModel objects produced during training.

#### Process
For each word in the set of test sentences:

* Get the context (i.e. features) associated with that word
* Use the appropriate averaged perceptron model to evaluate the given context
* Compare the guess provided by the model's evaluation to the known tag, or label
* Compute the accuracy, precision, recall, and f-score for the model

#### Output
A csv file of the test results.