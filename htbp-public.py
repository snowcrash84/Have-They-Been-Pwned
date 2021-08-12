#Author: Roman Mironov (https://github.com/snowcrash84/)
#Version: 0.6

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue


from burp import IScannerListener
from java.io import PrintWriter

from burp import ITab

from burp import IBurpExtenderCallbacks

from array import array

from javax import swing
from java.awt import BorderLayout
import sys
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

import base64

import time
import urllib
import urllib2
from urllib2 import HTTPError

import binascii
import cgi
import json

#potentially not needed:
import socket
import threading
import re



#Stock Test Strings
GREP_STRING = "@"
GREP_STRING_BYTES = bytearray(GREP_STRING)

#Enter your Have I Been Pwned API Key here:
hibp_api_key = 'API_KEY'


def htbp(self):
    global result
    global compromised_emails
    
    
    url = "https://haveibeenpwned.com/api/v3/breachedaccount/"+email    
    req = urllib2.Request(url)
    req.add_header('hibp-api-key',hibp_api_key)
    req.add_header('user-agent','burp')
    
    try:
        resp = urllib2.urlopen(req)
        content =  resp.read()
        result = resp.getcode()
        time.sleep(5)
        print "result in here is: " 
        print result
        if result == 200:
            print "Email compromised: " + email
            compromised_emails.append(email)
            

    except HTTPError as err:
        if err.code == 404:
            result = "404"
            
        else:    
            print "Error code " + str(err.code) + " for user " + email
            result = "error"
    
    
    # self.b64EncField.text = content
    return result
    
class BurpExtender(IBurpExtender, IScannerCheck, ITab, IBurpExtenderCallbacks):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks      
        self._helpers = callbacks.getHelpers()
        # Required for easier debugging: 
        # https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()
        
        # Set our extension name
        self.callbacks.setExtensionName("Have They Been Pwned?")

        # Keep a reference to our callbacks object




        #scanner listener stuff
        # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        
        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)
        
        # register ourselves as a Scanner listener
        #callbacks.registerScannerListener(self)

        

        # Create the tab
        self.tab = swing.JPanel(BorderLayout())
        
        # Create the text area at the top of the tab
        textPanel = swing.JPanel()
        
        # Create the label for the text area
        boxVertical = swing.Box.createVerticalBox()
        boxHorizontal = swing.Box.createHorizontalBox()
        textLabel = swing.JLabel("Email Addresses to check against HaveIBeenPwned:")
        boxHorizontal.add(textLabel)
        boxVertical.add(boxHorizontal)

        # Create the text area itself
        boxHorizontal = swing.Box.createHorizontalBox()
        self.textArea = swing.JTextArea('', 6, 100)
        self.textArea.setLineWrap(True)
        boxHorizontal.add(self.textArea)
        boxVertical.add(boxHorizontal)

        # Add the text label and area to the text panel
        textPanel.add(boxVertical)

        # Add the text panel to the top of the main tab
        self.tab.add(textPanel, BorderLayout.NORTH) 
        
        # Button for first tab
        buttonPanel = swing.JPanel()
        buttonPanel.add(swing.JButton('Have They Been Pwned?', actionPerformed=self.button_pressed))
        boxVertical.add(buttonPanel, "South")

        # Created a tabbed pane to go in the center of the
        # main tab, below the text area
        tabbedPane = swing.JTabbedPane()
        self.tab.add("Center", tabbedPane);

        # First tab
        firstTab = swing.JPanel()
        firstTab.layout = BorderLayout()
        tabbedPane.addTab("Compromised Accounts", firstTab)



        # Panel for the encoders. Each label and text field
        # will go in horizontal boxes which will then go in 
        # a vertical box
        encPanel = swing.JPanel()
        boxVertical = swing.Box.createVerticalBox()
        
        boxHorizontal = swing.Box.createHorizontalBox()
        self.b64EncField = swing.JTextArea('', 6, 100)
        # boxHorizontal.add(swing.JLabel("  Emails:"))
        boxHorizontal.add(self.b64EncField)
        boxVertical.add(boxHorizontal)



        # Add the vertical box to the Encode tab
        firstTab.add(boxVertical, "Center")
        
        # Second tab
        #secondTab = swing.JPanel()
        #secondTab.layout = BorderLayout()
        #tabbedPane.addTab("Not Compromised", secondTab)
        
        # Panel for the encoders. Each label and text field
        # will go in horizontal boxes which will then go in 
        # a vertical box
        not_compPanel = swing.JPanel()
        not_compBoxVertical = swing.Box.createVerticalBox()
        
        not_compBoxHorizontal = swing.Box.createHorizontalBox()
        self.not_compField = swing.JTextArea('', 6, 100)
        # boxHorizontal.add(swing.JLabel("  Emails:"))
        not_compBoxHorizontal.add(self.not_compField)
        not_compBoxVertical.add(not_compBoxHorizontal)

        
        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        return

    

    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets
    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen
            


        return matches
    
    #
    # implement IScannerCheck
    #

    def doPassiveScan(self, baseRequestResponse):
        # look for matches of our passive check grep string
        global compromised_emails
        compromised_emails = []
        global email
        
        reqres = baseRequestResponse.getResponse()
        matches = self._get_matches(reqres, GREP_STRING_BYTES)
        if (len(matches) == 0):
            return None
        else:
            response = self._helpers.bytesToString(reqres)
            

            regex_search = re.findall(r'[\w\.-]+@[\w\.-]+(?:\.[\w]+)+', response)
            #remove duplicates:
            email_found = list(dict.fromkeys(regex_search))

            if email_found:
                    print "Emails found:" 
                    print email_found
                    pwned_emails = []
                    for email in email_found:
                        result = ""
                        
                        print email
                        result = htbp(email)
                        
                        print "what is the result?"
                        print result
                        print "has this email been pwned?" + email
                        if result == 200:
                            
                            print "Pwned email:" + email
                            pwned_emails.append(email)
                            print "all pwned emails: "
                            print pwned_emails

                        else:
                            print "Email not pwned: " + email
                    
                    if pwned_emails:
                       return [CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [self.callbacks.applyMarkers(baseRequestResponse, None, None)],
                        "Email in Public Data Breach",
                        "The following emails were found in public breaches: <br><ul><li>" + '<li>'.join(pwned_emails) + "</ul>",
                        "Email addresses within the assessed application were discovered within one or more public data breach databases. Attackers who have access to the breached data can potentially compromise the affected user account if credentials have not been changed.",
                        "High", 
                        "Certain", 
                        "Ensure that user accounts are configured with secure passwords which are often changed; Implement Two-Factor Authentication where possible.")]
                    else:
                        return
 


    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0

    # Implement the functions from the button clicks
    def button_pressed(self, event):
        
        """Runs the code when button is
        pressed
        """
        global email
        global compromised_emails
        global not_compromised
        compromised_emails = []
        not_compromised = []        
        
        emails_submitted = self.textArea.text
        
        emails_split = emails_submitted.splitlines()
        # email_count = len(emails_split)   

        for email in emails_split:
            htbp(email)
        print('\n'.join(map(str, compromised_emails))) 
        # self.b64EncField.text = str(compromised_emails)
        self.b64EncField.text = '\n'.join(map(str, compromised_emails))

        

        
    # Implement ITab
    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "Have They Been PWNED?"
    
    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.tab

#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, description, severity, confidence, remediation):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._description = description
        self._severity = severity
        self._confidence = confidence
        self._remediation = remediation
        return

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return self._description

    def getRemediationBackground(self):
        return self._remediation

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService



try:
    FixBurpExceptions()
except:
    pass
    
