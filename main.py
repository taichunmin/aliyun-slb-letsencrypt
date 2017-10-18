#!/usr/bin/env python
# -*- coding: utf8 -*-

from __future__ import print_function
from os.path import join, dirname
from dotenv import load_dotenv, find_dotenv
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from aliyunsdkcore.client import AcsClient
from aliyunsdkslb.request.v20140515 import DescribeLoadBalancerHTTPSListenerAttributeRequest, DescribeServerCertificatesRequest, UploadServerCertificateRequest, SetLoadBalancerHTTPSListenerAttributeRequest, DeleteServerCertificateRequest
from aliyunsdkcore.acs_exception.exceptions import ServerException, ClientException
import datetime, os, collections, json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

load_dotenv(find_dotenv(), verbose=True)
aliyunAccessKeyId = os.environ.get("ALIYUN_ACCESS_KEY_ID")
aliyunAccessKeySecret = os.environ.get("ALIYUN_ACCESS_KEY_SECRET")
letsencryptLive = join(os.environ.get("LETSENCRYPT_PATH"), 'live')
slbCertificateLetsencrypt = json.loads(os.environ.get("SLB_CERTIFICATE_LETSENCRYPT"))
client = AcsClient(aliyunAccessKeyId, aliyunAccessKeySecret, 'cn-beijing')

# 獲取證書 md5 返回: 字典
def getLetsencryptFingerprint(domain):
    cert_file_string = open(join(letsencryptLive, domain, 'cert.pem'), "rb").read()
    cert = load_certificate(FILETYPE_PEM, cert_file_string)

    return cert.digest("sha1").lower()

def DescribeLoadBalancerHTTPSListenerAttribute(LoadBalancerId, ListenerPort):
    # print('debug =', LoadBalancerId, ListenerPort)
    request = DescribeLoadBalancerHTTPSListenerAttributeRequest.DescribeLoadBalancerHTTPSListenerAttributeRequest()
    request.set_accept_format('json')
    request.set_LoadBalancerId(LoadBalancerId)
    request.set_ListenerPort(ListenerPort)
    result = client.do_action_with_exception(request)
    return json.loads(result)

def DescribeServerCertificates(ServerCertificateId):
    # print('debug =', ServerCertificateId)
    request = DescribeServerCertificatesRequest.DescribeServerCertificatesRequest()
    request.set_accept_format('json')
    request.set_ServerCertificateId(ServerCertificateId)
    result = client.do_action_with_exception(request)
    return json.loads(result)['ServerCertificates']['ServerCertificate'][0]

def UploadServerCertificate(domain):
    # print('debug =', domain)
    request = UploadServerCertificateRequest.UploadServerCertificateRequest()
    request.set_accept_format('json')
    ServerCertificateName = datetime.datetime.now().strftime("%m%d%Y") + '_' + domain
    request.set_ServerCertificateName(ServerCertificateName)
    ServerCertificate = open(join(letsencryptLive, domain, 'fullchain.pem')).read()
    request.set_ServerCertificate(ServerCertificate)
    PrivateKey = loadLetsencryptPKeyToRsa(domain)
    request.set_PrivateKey(PrivateKey)
    result = client.do_action_with_exception(request)
    return json.loads(result)

def SetLoadBalancerHTTPSListenerAttribute(listener, LoadBalancerId, ServerCertificateId):
    request = SetLoadBalancerHTTPSListenerAttributeRequest.SetLoadBalancerHTTPSListenerAttributeRequest()
    for ik, iv in listener.iteritems():
        attrName = 'set_' + ik
        if hasattr(request, attrName) and callable(getattr(request, attrName)):
            request.add_query_param(ik, iv)
    request.set_accept_format('json')
    request.set_LoadBalancerId(LoadBalancerId)
    request.set_ServerCertificateId(ServerCertificateId)
    result = client.do_action_with_exception(request)
    return json.loads(result)

def DeleteServerCertificate(ServerCertificateId):
    request = DeleteServerCertificateRequest.DeleteServerCertificateRequest()
    request.set_accept_format('json')
    request.set_ServerCertificateId(ServerCertificateId)
    result = client.do_action_with_exception(request)
    return json.loads(result)

def loadLetsencryptPKeyToRsa(domain):
    # print('debug =', domain)
    pem_str = open(join(letsencryptLive, domain, 'privkey.pem'), "rb").read()
    private_key = serialization.load_pem_private_key(
        pem_str,
        password=None,
        backend=default_backend()
    )
    return private_key.private_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PrivateFormat.TraditionalOpenSSL,
       encryption_algorithm=serialization.NoEncryption()
    )

if __name__ == "__main__":
    # get all needed certificate fingerprints
    for lbId, iv in slbCertificateLetsencrypt.iteritems():
        for port, domain in iv.iteritems():
            try:
                print('')
                print('LoadBalancerId = ' + lbId + ', Port = ' + port + ', domain = ' + domain)
                fingerprint = getLetsencryptFingerprint(domain)
                print('Local fingerprint: ' + fingerprint)
                listener = DescribeLoadBalancerHTTPSListenerAttribute(lbId, port)
                certificate = DescribeServerCertificates(listener['ServerCertificateId'])
                print('Listener fingerprint: ' + certificate['Fingerprint'])
                if fingerprint != certificate['Fingerprint']:
                    print('Upload new certificate...')
                    newCertificate = UploadServerCertificate(domain)
                    print('new ServerCertificateId = ' + newCertificate['ServerCertificateId'])
                    SetLoadBalancerHTTPSListenerAttribute(listener, lbId, newCertificate['ServerCertificateId'])
                    print('Set to New ServerCertificate Success!')
                    DeleteServerCertificate(listener['ServerCertificateId'])
                    print('Deleted old ServerCertificateId = ' + listener['ServerCertificateId'])
                print('')
            except Exception as e:
                print(e)
