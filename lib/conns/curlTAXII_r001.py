

import pycurl
import cStringIO
import random


def main():

    # ## Note the crtName and crtPass are only need if twoway auth is enable
    conn_cred = {
        'URI': 'http://192.168.1.104/taxii-discovery-service',
        'usrName': 'admin',
        'usrPass': '',
        'crtName': None,
        'crtPass': None
    }

    print snd_taxii(conn_cred, getfile_xml('STIX_src_82.xml'))


def snd_taxii(conn_cred, xml):

    url = conn_cred['URI']
    if 'https' in url:
        ssl_flag = True
    else:
        ssl_flag = False

    xml = add_taxii_msg_block(xml)
    header = gen_taxii_post_header(xml, ssl_flag)
    response = connector(conn_cred, header, xml, ssl_flag)

    return response
    
def getfile_xml(file_name):
    file_obj = open(file_name, "r")
    xml = file_obj.read()
    file_obj.close()
    return xml


# ### --------------------------------------------------------------
# ## Everything below this point can be replaced by libtaxii and would have much better error codes
# ## But this MUCH simpler to understand
# ### --------------------------------------------------------------

def connector(conn_cred, headers, xml, ssl_flag):
    buf = cStringIO.StringIO()
        
    conn = pycurl.Curl()
    conn.setopt(pycurl.VERBOSE, False)
    conn.setopt(pycurl.URL, conn_cred['URI'])
    conn.setopt(pycurl.USERPWD, conn_cred['usrName'] + ':' + conn_cred['usrPass'])
    conn.setopt(pycurl.HTTPHEADER, headers)
    conn.setopt(pycurl.POST, 1)
    conn.setopt(pycurl.TIMEOUT, 999999)
    conn.setopt(pycurl.WRITEFUNCTION, buf.write)
    conn.setopt(pycurl.POSTFIELDS, xml)
    
    if ssl_flag:
        conn.setopt(pycurl.SSLVERSION, 3)
        if conn_cred['crtName']:
            conn.setopt(pycurl.SSLCERT, conn_cred['crtName'])
        if conn_cred['crtPass']:
            conn.setopt(pycurl.SSLKEYPASSWD, conn_cred['crtPass'])

    conn.perform()
    response = buf.getvalue()
    buf.close()

    return response


def gen_taxii_post_header(xml, ssl_flag):
    headers = []
    headers.append("Content-Type: application/xml")
    headers.append("Content-Length: " + str(len(xml)))

    # ## If posting outside your own org you should id yourself to help if there are errors
    headers.append("User-Agent: TAXII Client Application")

    headers.append("Accept: application/xml")
    headers.append("X-TAXII-Accept: urn:taxii.mitre.org:message:xml:1.1")
    headers.append("X-TAXII-Content-Type: urn:taxii.mitre.org:message:xml:1.1")
    if ssl_flag:
        headers.append("X-TAXII-Protocol:urn:taxii.mitre.org:protocol:https:1.1")
    else:
        headers.append("X-TAXII-Protocol:urn:taxii.mitre.org:protocol:http:1.1")

    return headers


def add_taxii_msg_block(xml):

    if len(xml) < 2:
        return None

    # The msg_id needs to resemble a number like this 1564343186463486, at least in length and I assume all zero would be bad
    msg_id = str(random.randrange(100000000000000, 999999999999999))

    hdr = "<?xml version='1.0' encoding='UTF-8'?><taxii:Inbox_Message xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xmlns:taxii='http://taxii.mitre.org/messages/taxii_xml_binding-1.1' message_id='" + msg_id + "'><taxii:Content_Block><taxii:Content_Binding binding_id='urn:stix.mitre.org:xml:1.1'/><taxii:Content>"
    ftr = "</taxii:Content></taxii:Content_Block></taxii:Inbox_Message>"

    xml = hdr + '\n' + xml + '\n' + ftr
    return xml
    
if __name__ == "__main__":
    main()

#eof

