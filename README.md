
## Traceroute Analysis


#### Author: Jordan McKinney

#### Course: CSC 361


### Overview

This project consists of a basic traceroute analyzer written
in C. 

The program takes a capture file as input and outputs a summary
of any traceroute activity captured.


### Compilation/Execution

To compile and run the program with the included sample file
(input/trace1.pcapng) simply type 'make' into the command
line. The program will output to 'output/out1.txt'. 

To run the program with a different input file, add the file 
to the input folder and type:

`make INPUT="input/myinputfile.pcapng"`

To send the output to a different output file type:

`make OUTPUT="output/myoutput.txt"`

Both options can be combined as:

`make INPUT="input/myinputfile.pcapng" OUTPUT="output/myoutput.txt"`

To run the program on ALL of the included input files go in to 
the makefile and uncomment all the commented lines.
After doing this and saving the makefile, type 'make' into 
the command line as before. 


### Sources

Parts of traceroute.c as well as the error handling functions were 
borrowed from the previous assignment. These originally came from 
the course connex page. 