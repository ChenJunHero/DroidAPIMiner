#!/usr/bin/env python
# -*- coding: utf-8 -*-
from dataflowanalysis import *
from external_api import *
import os
apk_dir = "SampleApplication.apk"
#all external api calls and data flow analysis
def result(x):
    '''
    :param x: an apk file
    :return:  a list of api_calls and data_flow_results
    '''
    return get_api_calls(x) + data_flow_result(x)


for apk in os.listdir("test_apk"):
    # print(apk)
    apk_path = os.path.join("test_apk",apk)
    print(apk_path)
    print(os.path.basename(apk_path).rstrip(".apk"))
    apk_name = os.path.basename(apk_path).rstrip(".apk")
    result_dir = "Report/" + apk_name +  ".txt"
    with open(result_dir ,"w+") as f:
        for i in result(apk_path):
            f.write(str(i) + "\n")
    print(result(apk_path))