#coding:utf-8
'''
Created on 2017/11/30

@author: gy071089
'''

import requests,time
import json
from requests.packages import urllib3

url = 'url'
verify = False
token = ''
apikey = 'API-KEY'

def build_url(resource):
    return '{0}{1}'.format(url, resource)

def connect(method, resource, data=None):
    headers = {
               'content-type': 'application/json',
               'X-Auth':apikey,
               }
    data = json.dumps(data)
    urllib3.disable_warnings()
    try:
        if method == 'POST':
            r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'PUT':
            r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'DELETE':
            r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'PATCH':
            r = requests.patch(build_url(resource), data=data, headers=headers, verify=verify)
        else:
            r = requests.get(build_url(resource), params=data, headers=headers, verify=verify)
    except Exception as e:
        return False
    
    # Exit if there is an error.
    if r.status_code == 204:
        return True
    elif r.status_code != 200:
        e = r.json()
        return e
    
    if 'download' in resource:
        return r.content
    else:
        return r.json()

def connect_all(method, resource, data=None):
    '''
    这个和上一个区别是返回信息完整
    '''
    headers = {
               'content-type': 'application/json',
               'X-Auth':apikey,
               }
    data = json.dumps(data)
    urllib3.disable_warnings()
    try:
        if method == 'POST':
            r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'PUT':
            r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'DELETE':
            r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'PATCH':
            r = requests.patch(build_url(resource), data=data, headers=headers, verify=verify)
        else:
            r = requests.get(build_url(resource), params=data, headers=headers, verify=verify)
    except Exception as e:
        return e
    return r

#添加目标信息
def add(address, desc):
    scan = {
            'address': address,
            'description':desc,
            'criticality':'10',
            }
    
    data = connect('POST', '/api/v1/targets', data=scan)
    
    return data['target_id']

#获取所有扫描信息
def getscan():
    scans  = connect('GET', '/api/v1/scans')
    return scans

#获取扫描的scan_id
def getscanid(target_id):
    
    scans  = connect('GET', '/api/v1/scans')
    for scan in scans['scans']:
        if scan['target_id'] == target_id:
            scan_id = scan['scan_id']
            return scan_id
    if scan_id:
        return scan_id

#获取扫描状态
def getstatus(scan_id):
    
    data = connect('GET', '/api/v1/scans/{0}'.format(scan_id))
    
    status = data['current_session']['status']
    
    return status

#获取扫描的scan_session_id
def getsessionsid(scan_id):
    
    data = connect('GET', '/api/v1/scans/{0}'.format(scan_id))
    
    scan_session_id = data['current_session']['scan_session_id']
    
    return scan_session_id

#删除扫描任务
def delete(scan_id):
    
    data = connect('DELETE', '/api/v1/scans/{0}'.format(scan_id))
    
    return data

#停止扫描任务
def stop(scan_id):
    
    data = connect('POST', '/api/v1/scans/{0}/abort'.format(scan_id))
    
    return data

#开始扫描任务
def start(target_id):
    '''
    11111111-1111-1111-1111-111111111112    High Risk Vulnerabilities          
    11111111-1111-1111-1111-111111111115    Weak Passwords        
    11111111-1111-1111-1111-111111111117    Crawl Only         
    11111111-1111-1111-1111-111111111116    Cross-site Scripting Vulnerabilities       
    11111111-1111-1111-1111-111111111113    SQL Injection Vulnerabilities         
    11111111-1111-1111-1111-111111111118    quick_profile_2 0   {"wvs": {"profile": "continuous_quick"}}            
    11111111-1111-1111-1111-111111111114    quick_profile_1 0   {"wvs": {"profile": "continuous_full"}}         
    11111111-1111-1111-1111-111111111111    Full Scan   1   {"wvs": {"profile": "Default"}}         
    '''
    scan = {
            'target_id':target_id,
            'profile_id':'11111111-1111-1111-1111-111111111111',
            'schedule':{
                        'disable':False,
                        'start_date':None,
                        'time_sensitive':False,
                        }
            }
    data = connect('POST', '/api/v1/scans',data=scan)
    
    return data

#这个是配置信息，只写了部分
def configure(target_id,cookie,url):
    
    conf = {
            'custom_cookies':[{'url':url,'cookie':cookie}]
            }
    res = connect('PATCH', '/api/v1/scans/{0}/configuration'.format(target_id),data = conf)
    if res:
        data = start(target_id)
    return data


#获取扫描报告的下载地址，主要是xml格式，方便进行处理，也可生成pdf呵呵html格式，看个人需求
def getreport(scan_id):
    '''
    11111111-1111-1111-1111-111111111111    Developer
    21111111-1111-1111-1111-111111111111    XML
    11111111-1111-1111-1111-111111111119    OWASP Top 10 2013 
    11111111-1111-1111-1111-111111111112    Quick
    '''
    data = {'template_id':'21111111-1111-1111-1111-111111111111','source':{'list_type':'scans','id_list':[scan_id]}}
    
    response  = connect_all('POST','/api/v1/reports',data=data)
     
    header = response.headers
    
    report = url + header['Location'].replace('/api/v1/reports/','/reports/download/') + '.xml'
    
    time.sleep(10)
    return report

#获取单个扫描的全部信息
def getstatistics(scan_id,scan_session_id):
    
    data = connect('GET', '/api/v1/scans/{0}/results/{1}/statistics'.format(scan_id,scan_session_id))
    
    return data

#获取单个扫描的漏洞列表，如果需要查询漏洞详细信息的话
def getscanvulns(scan_id,scan_session_id):
    
    data = connect('GET', '/api/v1/scans/{0}/results/{1}/vulnerabilities'.format(scan_id,scan_session_id))
    
    return data

    
if __name__ == '__main__':
    '''
    #如果扫描的话，目标地址，只接受http或者https开头的其他的都不接受
    target_id = add('url','this is a test')
    res = delete(target_id)
    res_start = start(target_id)
    scan_id = getscanid(target_id)
    status = getstatus(scan_id)
    res_stop = stop(scan_id)
    delete = delete(scan_id)'''
    target_id = add('url','this is a test')
    data = start(target_id)
    scan_id = getscanid(target_id)
    scan_session_id = getsessionsid(scan_id)
    data = getstatistics(scan_id,scan_session_id)
    data_vuln = getscanvulns(scan_id,scan_session_id)
    print(data)
    



