# XSS Scanner
XSS scanner based on Chromium.

* This scaner can perform simple checks for Reflected XSS in GET/POST parameters. It looks for alert(1) to appear, and log all results in xss.log
* When used with [untrusted types](https://github.com/filedescriptor/untrusted-types) it can monitor for DOM XSS. All console output from this pluggin is logged in ./chromedata/chrome\_debug.log. Also can send postMessage to the current window with the DOM XSS keyword.
* Could perform verification for the list of given urls with Reflected XSS in GET parameters
* It can also extract variable names from Java Scrips on the page. 

## OPTIONS:

```
--all    - do checks for XSS in GET,POST parameters. Send postMessage with the dom xss keyword
--get    - do checks for XSS in GET parameters
--post   - do checks for XSS in POST parameters
--pm     - send postMessage
--domxss - do additional checks for the dom xss

--validate    - validate urls from the given list. Should be used separately from --all, --get,--post params
--save_images - save screenshoots while validation.
--extractjs   - add additional parameter names from js on the page
 
--visible     - run Chromium in visible mode
--load_images - force scanner to load images on the page
--proxy       - specify proxy
--cookies     - load saved cookies

--payloads  - specify list with XSS payloads (i.e. ./xss_payloads)
--variables - specify list with parameter names (i.e. ./params.list from ParamMiner Burp plugin)
--urls      - url list to check
--url       - single url to check
--kill      - (obsolete) kill all previus instances of chromedriver
```

You can also login on the target domains manually (to set auth Cookies, etc.) by running scaner with these parameters: 
./xss.py --cookie --visible

After that you can use --cookie param to load saved cookies.

**To perform post requests you have to run ./post-proxy.py.**
It just creates clear page on the localhost, then scaner runs js in console and create form with required parameters, then click the form submit button and do post request.

## INSTALLATION
Those Python packages are required:
selenium
flask
requests
lxml

You have to download [Chromium Driver](https://chromedriver.chromium.org/).
It version must correspond to the version of chromium-browser on your system
The path to the chromium-driver must be specified in ./settings.py

