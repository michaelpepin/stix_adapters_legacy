
###
#
#   ### -----< Message Managment Functions >-----
#   sndMSG(),   return None
#   sendMail(), return None || status
#
###

# -----< Message Managment Functions >-----

import os
import sys
from datetime import datetime

def log(msg,type_="INFO",src=None):
    """

    :param msg: <string>
    :param type_: <string> default:INFO
    :param src: <object> sys._getframe()
    :return: <boolean>

    usage: log('Send Email', 'INFO', sys._getframe())
    """
    LOG_PRINT = True
    LOG_EMAIL = True

    date_time = str(datetime.now())
    msg_header = '| %s | %s ' % (date_time, type_)
    if isinstance(src, object):
        msg_header += '| %s:%s ' % (src.f_code.co_name, src.f_lineno)

    msg_str = "%s | %s" % (msg_header, msg)

    if LOG_PRINT:
        print msg_str

    if str(type_).lower() == 'error':
        if LOG_EMAIL:
            snd_mail(msg_str, subject='ErrorMsg')


def snd_mail(msg, **kwargs):
    import os.path
    import socket

    mail_agent = "/usr/sbin/sendmail"
    if not os.path.isfile(mail_agent):
        log('ERROR[%s does not exist]: This system can not send mail' % mail_agent, 'INFO', sys._getframe())
        return False

    sbj_hdr = str(socket.gethostname())
    if kwargs.get('subject'):
        sbj_hdr += ' | %s ' % kwargs.get('subject')
    else:
        sbj_hdr += ' | ErrorMsg '

    # TODO: handle from_ to_
    # TODO: handle to_ as both a str and list
    # TODO: input validate check is valid email address format

    try:
        post = os.popen4("%s -t" % mail_agent, "w")

    finally:
        post = os.popen("%s -t" % mail_agent, "w")

    if post:
        post.write("From: %s\n" % "root@hailataxii.com")
        post.write("To: %s\n" % "michael.pepin@gmail.com")
        post.write("Subject: " + sbj_hdr + "\n")
        post.write("\n") # blank line separating headers from body
        post.write(msg)
        status = post.close()
        if status != 0:
            log('ERROR: Email was not sent. code:%s' % status, 'INFO', sys._getframe())
        else:
            log('Email was sent. code:%s' % status, 'INFO', sys._getframe())

    # TODO: look into MIME
    #   from email.mime.text import MIMEText
    #   MIMEText

