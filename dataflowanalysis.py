#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@class------------------@methods------------------@parameters-------------------------------------------
Intent                  setFlags,addFlags         CALL, CONNECTIVITY, SEND, SENDTO,
IntentFilters           setDataAndType            or BLUETOOTH 
                        putExtra,init
--------------------------------------------------------------------------------------------------------
ContentResolver         query, insert,            Content://sms-mms, Content://telephony,
                        update                    Content://calendar, Content://browser/bookmarks,
                                                  Content://calllog, Content://mail,
                                                  or Content://downlaods                      
--------------------------------------------------------------------------------------------------------
DataInputStream         init, writeBytes          Reads from process
BufferedReader                                    Reads from connection
DataOutputStream                                  Uses SU command
DataOutputStream                                                 
--------------------------------------------------------------------------------------------------------
InetSocketAddress       init                      parameter IP is explicit or port is 80
--------------------------------------------------------------------------------------------------------
File                    init, write, append,      Dangerous Command such as: su, ls, loadjar, grep,
Stream                                            /sh, /bin, pm install, /dev/net, insmod, rm, mount,
StringBuilder                                     root, /system, stdout, reboot, killall, chmod, stderr
String                  indexOf, Substring        Accesses external storage or cache
StringBuffer                                      An identifier (e.g. Imei), an executable file( e.g. .exe,
                                                  .sh), a compressed file (e.g. jar, zip), a unicode string,
                                                  an sql query, a reflection string, or a url
---------------------------------------------------------------------------------------------------------
'''
from __future__ import print_function

from androwarn.analysis.analysis import *

def detect_connection(x):
    '''
    :param x:  a VMAnalysis instance
    :return:   a formatted strings
    '''
    formatted_str = ["Ljava/net/InetSocketAddress.<init>[Detected remote address and IP port]"]
    local_formatted_str = []
    connection_methods = [["Ljava/net/Socket","<init>"],["Ljava/net/InetSocketAddress","Ljava/net/InetSocketAddress"]]
    for i in range(len(connection_methods)):
        structural_analysis_results = x.tainted_packages.search_methods(connection_methods[i][0],connection_methods[i][1] , ".")
        # print(structural_analysis_results)
        for result in xrange(len(structural_analysis_results)):
            registers = data_flow_analysis(structural_analysis_results, result, x)
            # print(registers)
            if len(registers) >= 2:
                remote_address = get_register_value(1,registers)  # 1 is the index of the PARAMETER called in the method
                # print(remote_address)
                remote_port = get_register_value(2, registers)

                local_formatted_str.append("remote address '%s' on the '%s' port " % ( remote_address, remote_port))
    if local_formatted_str != []:
        return formatted_str
    else: return []


#detect the parameters of Intent class
def get_intent_parameter(x):
    '''
    @:param x : a list of registers relating Intent parameter value 
    @:rtype : a list of intent api calls including parameter value
    '''
    value_option = ("CALL", "CONNECTIVITY", "SEND", "SENDTO", "BLUETOOTH")
    value =  []
    for i in range(len(x)):
        parameter = get_register_value(i,x)

        # print(parameter)
        for j in range(len(value_option)):
            if value_option[j] in parameter:
                value.append(value_option[j])
    return value
def detect_intent(x):
    '''
    :param x: a VMAnalysis instance
    :return:  a list of formatted strings
    '''
    formatted_str = []

    intent_methods = [["Landroid/content/Intent","<init>"],
                      ["Landroid/content/Intent","setFlags"],
                      ["Landroid/content/Intent","addFlags"],
                      ["Landroid/content/Intent","putExtra"],
                      ["Landroid/content/Intent","setDataAndType"],
                      ["Landroid/content/IntentFilter","<init>"]]

    for i in range(len(intent_methods)):
        structural_analysis_results = x.tainted_packages.search_methods(intent_methods[i][0],intent_methods[i][1] , ".")
        for results in xrange(len(structural_analysis_results)):
            registers = data_flow_analysis(structural_analysis_results, results, x)
            # print(registers)
            parameter_value = get_intent_parameter(registers)
            # print(parameter_value)
            if parameter_value != []:
                 [formatted_str.append(intent_methods[i][0] + "." + intent_methods[i][1] + "["+ j + "]") for j in parameter_value]
            # print(formatted_str)

    return list(set(formatted_str))




def get_data_parameter(x):
        '''
        @:param x : a list of registers relating file parameter value 
        @:rtype : a list of file api calls including parameter value
        '''
        value_option = ("su","read")
        value = []
        for i in range(len(x)):
            parameter = get_register_value(i, x)
            # print(parameter)
            for j in range(len(value_option)):
                if value_option[j] in parameter:
                    value.append(value_option[j])
        return value
#detect dataInputStream
def detect_data(x):
    formatted_str =[]
    s1 = x.tainted_packages.search_methods("Ljava/io/DataInputStream", "<init>", ".")
    s2 = x.tainted_packages.search_methods("Ljava/io/DataOutputStream", "<init>", ".")
    s3 = x.tainted_packages.search_methods("Ljava/io/BufferedReader", "<init>", ".")
    s4 = x.tainted_packages.search_methods("Ljava/io/DataInputStream", "writeBytes", ".")
    s5 = x.tainted_packages.search_methods("Ljava/io/DataInputStream", "writeBytes", ".")
    s6 = x.tainted_packages.search_methods("Ljava/io/BufferedReader", "writeBytes", ".")
    # print("data:s1,s2,s3,s4 s5 s6",s1,s2,s3,s4,s5,s6)
    data_apis = [["Ljava/io/DataInputStream", "<init>"],
                 ["Ljava/io/DataOutputStream", "<init>"],
                 ["Ljava/io/BufferedReader", "<init>"],
                 ["Ljava/io/DataInputStream", "writeBytes"],
                 ["Ljava/io/DataInputStream", "writeBytes"],
                 ["Ljava/io/BufferedReader", "writeBytes"]]
    for i in range(len(data_apis)):
        structural_analysis_results = x.tainted_packages.search_methods(data_apis[i][0],data_apis[i][1] , ".")
        for results in xrange(len(structural_analysis_results)):
            registers = data_flow_analysis(structural_analysis_results, results, x)
            # print(registers)
            parameter_value = get_file_parameter(registers)
            # print(parameter_value)
            if parameter_value != []:
                  [formatted_str.append(data_apis[i][0] + "." + data_apis[i][1] + "[" + j + "]") for j in parameter_value]
        # print(formatted_str)
    return list(set(formatted_str))
# detect_data(dx)
#
#detect file
def get_file_parameter(x):
        '''
        @:param x : a list of registers relating file parameter value 
        @:rtype : a list of file api calls including parameter value
        '''
        value_option = ("su", "ls", "loadjar", "grep", "/sh", "/bin", "pm install", "/dev/net", "insmod"
                        "rm", "mount", "root",
                        "/system", "stdout", "reboot", "killall",
                        "chmod", "stderr", "sdcard", "imei", "Imei", ".exe", ".sh", "jar"
                        , "zip", "\u", "query", "http","https")
        value = []
        for i in range(len(x)):
            parameter = get_register_value(i, x)
            # print(parameter)
            for j in range(len(value_option)):
                if value_option[j] in parameter:
                    value.append(value_option[j])
        return value
def detect_file(x):

    formatted_str = []
    file_apis = [["Ljava/io/File", "<init>"],
                 ["Ljava/util/stream/Stream", "<init>"],
                 ["Ljava/lang/StringBuilder", "<init>"],
                 ["Ljava/lang/String", "<init>"],
                 ["Ljava/lang/StringBuffer","<init>"],
                 ["Ljava/lang/StringBuilder", "append"],
                 ["Ljava/lang/String", "append"],
                 ["Ljava/lang/StringBuffer","append"],
                 ["Ljava/lang/StringBuilder", "indexOf"],
                 ["Ljava/lang/String", "indexOf"],
                 ["Ljava/lang/StringBuffer","indexOf"],
                 ["Ljava/lang/StringBuilder", "substring"],
                 ["Ljava/lang/String", "substring"],
                 ["Ljava/lang/StringBuffer","substring"]]
    for i in range(len(file_apis)):
        structural_analysis_results = x.tainted_packages.search_methods(file_apis[i][0],file_apis[i][1] , ".")
        # print(structural_analysis_results)
        for results in xrange(len(structural_analysis_results)):
            registers = data_flow_analysis(structural_analysis_results, results, x)
            # print(registers)
            parameter_value = get_file_parameter(registers)
            # print(parameter_value)
            if parameter_value != []:
                # print(parameter_value)
                [formatted_str.append(file_apis[i][0] + "." + file_apis[i][1] + "["+ j + "]") for j in parameter_value]
    # print(formatted_str)
    return list(set(formatted_str))

# detect_file(dx)

def get_content_parameter(x):
    '''
    @:param x : a list of registers relating file parameter value 
    @:rtype : a list of file api calls including parameter value
    '''
    value_option = ("content://sms-mms","content://sms","content://telephony",
                    "content://calendar","content://browser/bookmarks",
                    "content://calllog","content://mail","content://downloads")
    value = []
    for i in range(len(x)):
        parameter = get_register_value(i, x)
        # print(parameter)
        for j in range(len(value_option)):
            if value_option[j] in parameter:
                value.append(value_option[j])
    return value
#detect content
def detect_content(x):
    s1 = x.tainted_packages.search_methods("Landroid/content/ContentResolver", "query", ".")
    s2 = x.tainted_packages.search_methods("Landroid/content/ContentResolver", "insert", ".")
    s3 = x.tainted_packages.search_methods("Landroid/content/ContentResolver", "update", ".")
    # print("ContentResolver,s1,s2,s3",s1,s2,s3)
    formatted_str = []
    content_apis = [["Landroid/content/ContentResolver", "query"],["Landroid/content/ContentResolver", "insert"],["Landroid/content/ContentResolver", "update"]]
    for i in range(len(content_apis)):
        structural_analysis_results = x.tainted_packages.search_methods(content_apis[i][0], content_apis[i][1], ".")
        for results in xrange(len(structural_analysis_results)):
            registers = data_flow_analysis(structural_analysis_results, results, x)
            # print(registers)
            parameter_value = get_content_parameter(registers)
            # print(parameter_value)
            if parameter_value != []:
                [formatted_str.append(content_apis[i][0] + "." + content_apis[i][1] + "[" + j + "]") for j in parameter_value]
    # print(formatted_str)
    return list(set(formatted_str))

def data_flow_result(x):
    result = []
    a, d, dx = AnalyzeAPK(x)
    a1 = detect_connection(dx)
    a2 = detect_content(dx)
    a3 = detect_file(dx)
    a4 = detect_intent(dx)
    a5 = detect_data(dx)
    result = a1 + a2 + a3 + a4 +a5
    return result

if __name__ == "__main__":
    apk_dir = 'SampleApplication.apk'
    print(data_flow_result('SampleApplication.apk'))
    print(data_flow_result('0a7f.apk'))


