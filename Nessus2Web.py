#-------------------------------------------------------------------------------
# Name:        Nessus2Web
# Purpose:     Discover all the web services from a Nessus scan file and display
#              them in a list with their corresponding port after a colon
#
# Author:      Hom Kafle
#
# Created:     13/06/2018
# Copyright:   (c) hkafle 2018
#-------------------------------------------------------------------------------
import dotnessus_v2
import sys, getopt, os
def main(argv):
    inputfile = ''
    outputfile = ''
    noMappings = True  # Variable for changing xsl template if no findings
    try:
        opts, args = getopt.getopt(argv, "hi:o:", ["help", "ifile=", "ofile="])
    except getopt.GetoptError:
        print 'OptErr Nessus2Web.py -i <inputfile> -o <outputfile>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'Nessus2Web.py -i <inputfile> -o <outputfile>'
            sys.exit(2)
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg
    if (inputfile == '') or (outputfile == ''):
        print 'Please enter input and output files. Syntax: Nessus2Web.py -i <inputfile> -o <outputfile>'
        sys.exit(2)
    pt = dotnessus_v2.Report()
    pt.parse(inputfile)
    f=open(outputfile,'w')
    for t in pt.targets:
        for v in t.vulns:
            if v.get('svc_name') == 'www':
                #print t.name +":"+ v.get('port')
                f.write(t.name +":"+ v.get('port') +'\n')

if __name__ == '__main__':
    main(sys.argv[1:])
