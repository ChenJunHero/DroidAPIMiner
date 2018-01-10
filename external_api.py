#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import os
import sys
external_api_calls_path = (os.getcwd().replace("external_api","external_api_calls"))
sys.path.append(external_api_calls_path)
from androguard.misc import *
from external_api_calls.androguard.core.androconf import *
def get_api_calls(x):
    '''
    :param x: a vm instance 
    :return: an external methods' list 
    '''
    a, d, dx = AnalyzeAPK(x)
    methods = []
    external_classes = dx.get_external_classes()# XREFFROM to XREFTo
    for i in external_classes:
        class_name = i.get_vm_class()
        methods_list = class_name.get_methods()
        for method in methods_list:
            a = "%s" % method.get_class_name()
            b = "%s" % method.get_name()
            c = "%s" % method.get_descriptor()
            methods.append(a.rstrip(";") + "." + b + c)
    return list(set(methods))

if __name__ == "__main__":
    apk_dir = "SampleApplication.apk"
    a = get_api_calls(apk_dir)
    print(len(get_api_calls(apk_dir)), get_api_calls(apk_dir))

