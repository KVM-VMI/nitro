import os
import logging
import shutil
import datetime
import libvirt

from vmtest_helper import WindowsVMTestHelper, LinuxVMTestHelper

class LoggingLayer(object):

    @classmethod
    def testSetUp(cls, test_class):
        # clean old test directory
        test_dir_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), test_class._testMethodName)
        shutil.rmtree(test_dir_path, ignore_errors=True)
        os.makedirs(test_dir_path, exist_ok=True)
        test_class.script_dir = os.path.dirname(os.path.realpath(__file__))
        # chdir into this directory for the test
        test_class.origin_wd = os.getcwd()
        os.chdir(test_dir_path)
        # create logging file handler
        test_class.f_handler = logging.FileHandler('test.log', mode='w')
        logging.getLogger().addHandler(test_class.f_handler)
        logging.info('Starting test at {}'.format(datetime.datetime.now()))

    @classmethod
    def testTearDown(cls, test_class):
        # chdir back to original wd
        os.chdir(test_class.origin_wd)
        # remove file handler
        logging.info('Ending test at {}'.format(datetime.datetime.now()))
        logging.getLogger().removeHandler(test_class.f_handler)


class VMLayer(LoggingLayer):
    @classmethod
    def testSetUp(cls, test_class):
        con = libvirt.open('qemu:///system')
        test_class.domain = con.lookupByName(test_class.domain_name)
        test_class.vm = test_class.test_helper(test_class.domain)

    @classmethod
    def testTearDown(cls, test_class):
        test_class.vm.stop()
